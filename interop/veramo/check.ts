// Interoperability check: a Veramo DIDComm v2 client (@veramo/did-comm)
// against a running Almena mediator. Bob asks for mediation and picks up;
// Alice sends him a message through the mediator the way Veramo routes it
// (a `forward` to the mediator DID in Bob's service). Every message is packed
// and unpacked by Veramo; only the HTTP POST is ours, because Veramo's own
// transport does not read `return_route` replies.
//
//   MEDIATOR_DID=did:web:mediator.almena.id node check.ts
//   ALMENA_DOMAIN=mediator.example.org node check.ts   (did:web of that domain)
//
// Exit code 0 when every required step passes.

import { createAgent } from '@veramo/core'
import { DIDComm, DIDCommHttpTransport } from '@veramo/did-comm'
import {
  createV3DeliveryRequestMessage,
  createV3MediateRequestMessage,
  createV3RecipientQueryMessage,
  createV3RecipientUpdateMessage,
  createV3StatusRequestMessage,
} from '@veramo/did-comm'
import { DIDManager, MemoryDIDStore } from '@veramo/did-manager'
import { PeerDIDProvider, getResolver as peerResolver } from '@veramo/did-provider-peer'
import { DIDResolverPlugin } from '@veramo/did-resolver'
import { KeyManager, MemoryKeyStore, MemoryPrivateKeyStore } from '@veramo/key-manager'
import { KeyManagementSystem } from '@veramo/kms-local'
import { Resolver } from 'did-resolver'
import { getResolver as webResolver } from 'web-did-resolver'
import { randomUUID } from 'node:crypto'

const MEDIATOR =
  process.env.MEDIATOR_DID ?? `did:web:${process.env.ALMENA_DOMAIN ?? 'mediator.almena.id'}`
const SPEC_ENC = { enc: 'A256CBC-HS512' } // what DIDComm v2.0 requires for authcrypt
const MEDIA_TYPE = 'application/didcomm-encrypted+json'

const agent: any = createAgent({
  plugins: [
    new KeyManager({
      store: new MemoryKeyStore(),
      kms: { local: new KeyManagementSystem(new MemoryPrivateKeyStore()) },
    }),
    new DIDManager({
      store: new MemoryDIDStore(),
      defaultProvider: 'did:peer',
      providers: { 'did:peer': new PeerDIDProvider({ defaultKms: 'local' }) },
    }),
    new DIDResolverPlugin({ resolver: new Resolver({ ...peerResolver(), ...webResolver() }) }),
    new DIDComm({ transports: [new DIDCommHttpTransport()] }),
  ],
})

// ---- reporting ----

let failures = 0
async function step<T>(name: string, run: () => Promise<T>, required = true): Promise<T | undefined> {
  try {
    const result = await run()
    console.log(`  ok    ${name}`)
    return result
  } catch (err: any) {
    if (required) failures++
    console.log(`  ${required ? 'FAIL' : 'note'}  ${name}\n        ${err?.message ?? err}`)
    return undefined
  }
}

function expect(condition: unknown, what: string): asserts condition {
  if (!condition) throw new Error(what)
}

// ---- talking to the mediator ----

let endpoint = ''

/** POSTs a packed message; returns the status and the reply, if any. */
async function post(packed: string): Promise<{ status: number; reply?: string; text: string }> {
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': MEDIA_TYPE },
    body: packed,
  })
  const text = await response.text()
  const isDidcomm = response.headers.get('content-type')?.startsWith('application/didcomm')
  return { status: response.status, reply: isDidcomm ? text : undefined, text }
}

/** Authcrypts `message` from its `from` to the mediator, POSTs it and unpacks the reply. */
async function request(message: any, options: object = SPEC_ENC): Promise<any> {
  message.return_route ??= 'all' // Veramo's builders set it only on some messages
  const packed = await agent.packDIDCommMessage({ message, packing: 'authcrypt', options })
  const { status, reply, text } = await post(packed.message)
  expect(status === 200 && reply, `expected a reply, got HTTP ${status}: ${text}`)
  const { message: answer, metaData } = await agent.unpackDIDCommMessage({ message: reply })
  expect(metaData.packing === 'authcrypt', `reply packing ${metaData.packing}`)
  return answer
}

function plain(type: string, from: string, body: object = {}) {
  return { id: randomUUID(), type, from, to: [MEDIATOR], body }
}

// ---- the run ----

console.log(`Veramo client against ${MEDIATOR}\n`)

const mediatorDoc = await step('resolve the mediator DID (did:web)', async () => {
  const { didDocument, didResolutionMetadata } = await agent.resolveDid({ didUrl: MEDIATOR })
  expect(didDocument, `resolution failed: ${JSON.stringify(didResolutionMetadata)}`)
  const service = didDocument.service?.find((s: any) => s.type === 'DIDCommMessaging')
  const endpoints = [service?.serviceEndpoint].flat()
  endpoint = endpoints.map((e: any) => (typeof e === 'string' ? e : e?.uri)).find((u: string) => u?.startsWith('https://'))
  expect(endpoint, 'no HTTPS DIDComm endpoint in the DID document')
  return didDocument
})
if (!mediatorDoc) process.exit(1)

const bob = (await agent.didManagerCreate({
  provider: 'did:peer',
  options: {
    num_algo: 2,
    service: { type: 'DIDCommMessaging', serviceEndpoint: { uri: MEDIATOR, accept: ['didcomm/v2'] } },
  },
})).did as string
const alice = (await agent.didManagerCreate({ provider: 'did:peer', options: { num_algo: 2 } })).did as string

await step('Trust Ping 2.0: ping → ping-response', async () => {
  const answer = await request(plain('https://didcomm.org/trust-ping/2.0/ping', bob, { response_requested: true }))
  expect(answer.type === 'https://didcomm.org/trust-ping/2.0/ping-response', answer.type)
})

await step('Discover Features 2.0: queries → disclose', async () => {
  const answer = await request(
    plain('https://didcomm.org/discover-features/2.0/queries', bob, {
      queries: [{ 'feature-type': 'protocol', match: 'https://didcomm.org/*' }],
    }),
  )
  const ids = answer.body.disclosures.map((d: any) => d.id)
  for (const p of ['coordinate-mediation/3.0', 'messagepickup/3.0', 'routing/2.0'])
    expect(ids.includes(`https://didcomm.org/${p}`), `${p} not disclosed`)
})

await step('Coordinate Mediation 3.0: mediate-request → mediate-grant', async () => {
  const answer = await request(createV3MediateRequestMessage(bob, MEDIATOR))
  expect(answer.type === 'https://didcomm.org/coordinate-mediation/3.0/mediate-grant', answer.type)
  expect(answer.body.routing_did?.[0] === MEDIATOR, `routing_did ${JSON.stringify(answer.body.routing_did)}`)
})

await step('Coordinate Mediation 3.0: recipient-update (add) → success', async () => {
  const answer = await request(
    createV3RecipientUpdateMessage(bob, MEDIATOR, [{ recipient_did: bob, action: 'add' } as any]),
  )
  expect(answer.body.updated?.[0]?.result === 'success', JSON.stringify(answer.body))
})

await step('Coordinate Mediation 3.0: recipient-query → recipient', async () => {
  const answer = await request(createV3RecipientQueryMessage(bob, MEDIATOR))
  expect(answer.body.dids?.some((d: any) => d.recipient_did === bob), JSON.stringify(answer.body))
})

await step('Routing 2.0: Alice sends to Bob, Veramo wraps a forward to the mediator', async () => {
  const message = {
    id: randomUUID(),
    type: 'https://didcomm.org/basicmessage/2.0/message',
    from: alice,
    to: [bob],
    body: { content: 'hola Bob, desde Veramo' },
  }
  const packed = await agent.packDIDCommMessage({ message, packing: 'authcrypt', options: SPEC_ENC })
  await agent.sendDIDCommMessage({ packedMessage: packed, recipientDidUrl: bob, messageId: message.id })
})

await step('Message Pickup 3.0: status-request → status (1 waiting)', async () => {
  const answer = await request(createV3StatusRequestMessage(bob, MEDIATOR))
  expect(answer.type === 'https://didcomm.org/messagepickup/3.0/status', answer.type)
  expect(answer.body.message_count === 1, `message_count ${answer.body.message_count}`)
})

const delivered = await step('Message Pickup 3.0: delivery-request → delivery, opened by Bob', async () => {
  const answer = await request(createV3DeliveryRequestMessage(bob, MEDIATOR))
  expect(answer.type === 'https://didcomm.org/messagepickup/3.0/delivery', answer.type)
  const attachment = answer.attachments?.[0]
  expect(attachment?.data?.base64, 'no base64 attachment')
  const inner = Buffer.from(attachment.data.base64, 'base64url').toString('utf8')
  const { message, metaData } = await agent.unpackDIDCommMessage({ message: inner })
  expect(message.body.content === 'hola Bob, desde Veramo', JSON.stringify(message.body))
  expect(message.from === alice && metaData.packing === 'authcrypt', 'sender not authenticated')
  return attachment.id as string
})

await step('Message Pickup 3.0: messages-received → status (0 waiting)', async () => {
  expect(delivered, 'nothing was delivered')
  const answer = await request(
    plain('https://didcomm.org/messagepickup/3.0/messages-received', bob, { message_id_list: [delivered] }),
  )
  expect(answer.body.message_count === 0, `message_count ${answer.body.message_count}`)
})

// Veramo's defaults, which DIDComm v2.0 does not allow: reported, not required.
await step(
  "Veramo's default authcrypt (A256GCM content encryption) is refused",
  async () => {
    const packed = await agent.packDIDCommMessage({
      message: plain('https://didcomm.org/trust-ping/2.0/ping', bob),
      packing: 'authcrypt',
    })
    const { status, text } = await post(packed.message)
    expect(status === 400, `HTTP ${status}: ${text}`)
  },
  false,
)

console.log(failures === 0 ? '\nAll required steps passed.' : `\n${failures} required step(s) failed.`)
process.exit(failures === 0 ? 0 : 1)
