# Almena Mediator Specification

Version: draft 2 (2026-11-12) · Status: describes `almena-mediator` as implemented (phases 1–8, Appendix I).

This document specifies the Almena Mediator as a profile of, and a set of extensions to, [DIDComm Messaging v2.0][didcomm]. It does not restate DIDComm: wherever a behaviour is the one the referenced specification defines, it says so and points at it. What it does spell out is what Almena adds, restricts, interprets or leaves out.

Sections 1–13 are the contract: what a wallet, another mediator or another implementation can rely on. The appendices (non-normative) record how `almena-mediator` implements it and why each decision was taken. Read this document before DIDComm work and keep it current with every change.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in [RFC 2119][rfc2119] and [RFC 8174][rfc8174].

## 1. Scope

The Almena Mediator is a **pure mediator**: a mailbox that accepts DIDComm encrypted envelopes for the wallets it serves, queues them while those wallets are offline, and hands them over when they connect. It also relays envelopes for wallets mediated elsewhere and wakes mobile wallets with content-free push notifications.

- It MUST NOT decrypt messages addressed to anyone but itself. The only messages it opens are the administrative ones wallets send *to the mediator* (mediation, pickup, device registration, ping, feature discovery).
- A mediator is **public** (any wallet may keep its mailbox there) or **private** (only the wallets its administrators invite), fixed when it is set up. Its operators administer it from a web portal, signing in with the Almena wallet (App. G); the portal is not part of the DIDComm contract.
- Out of scope: message content and wallet-to-wallet protocols (Basic Message, chat), groups, user directories, a registry of mediators.

## 2. Sources

### 2.1 Normative

| Ref | Document | Used for |
|---|---|---|
| [DIDComm] | [DIF DIDComm Messaging v2.0][didcomm] (DIF-ratified) | Message format, envelopes, algorithms, routing, transports, Trust Ping, Discover Features, Report Problem, Out-of-Band. **v2.0, not v2.1** (v2.1 is only Working Group Approved). |
| [DID] | [W3C Decentralized Identifiers v1.0][did] | DIDs, DID documents, resolution. |
| [did:key] | [did:key Method][didkey] | Wallet and test DIDs. |
| [did:peer] | [Peer DID Method][didpeer] (numalgo 2 and 4) | Pairwise wallet DIDs. |
| [did:web] | [did:web Method][didweb] | Mediator DIDs. |
| [did:webvh] | [did:webvh Method 1.0][didwebvh] | DIDs of the Almena registry's tenants, issuers and verifiers. |
| [JOSE] | [RFC 7515][rfc7515] (JWS), [RFC 7516][rfc7516] (JWE), [RFC 7517][rfc7517] (JWK), [RFC 7518][rfc7518] (JWA), [RFC 7519][rfc7519] (JWT), [RFC 8037][rfc8037] (OKP) | Envelopes, keys, possession proofs. |
| [1PU] | [ECDH-1PU, draft-madden-jose-ecdh-1pu-04][ecdh1pu] | Authcrypt key agreement, as DIDComm v2.0 profiles it. |
| [XC20P] | [draft-amringer-jose-chacha][xc20p] | Optional content encryption. |
| [CoordMed] | [Coordinate Mediation 3.0][coordmed] | Mediation. |
| [Routing] | [Routing 2.0][routing] (DIDComm §Routing) | `forward`. |
| [Pickup] | [Message Pickup 3.0][pickup] | Polling and live delivery. |
| [ReturnRoute] | [Aries RFC 0092 Transports Return Route][rfc0092], as carried into DIDComm v2 | `return_route` header. |
| [FCM] | [Aries RFC 0734 Push Notifications FCM][rfc0734] | Device registration, FCM. Written for DIDComm v1; adapted in §6.3. |
| [APNs] | [Aries RFC 0699 Push Notifications APNs][rfc0699] | Device registration, APNs. Written for DIDComm v1; adapted in §6.3. |
| [Ack] | [Aries RFC 0015 ACKs][rfc0015] | The `ack` the push protocols answer with. |

### 2.2 Informative

- [Firebase Cloud Messaging HTTP v1 API][fcmapi] and [Apple Push Notification service][apnsapi] — the push back-ends.
- Implementations used for interoperability testing (§10): [didcomm-rust][sicpa] (SICPA), [affinidi-messaging-didcomm][affinidi] (DIDComm v2.1), [Veramo][veramo].
- [RustCrypto][rustcrypto] — the primitives `almena-didcomm` is built on. No JOSE or DIDComm library is used.

## 3. Profile of DIDComm v2.0

What [DIDComm] leaves open or optional, fixed for Almena.

### 3.1 Messages

- Plaintext messages follow [DIDComm] §Message Structure. Almena requires `body` on every message (as v2.0 does; v2.1 relaxed it): a message without it is rejected.
- `created_time` and `expires_time` are epoch seconds. The mediator MUST drop a message whose `expires_time` has passed (`e.m.req.time.expired`).
- `from_prior` is verified on unpack: signed by an `authentication` key of `iss`, `sub` = `from`, `iss` ≠ `sub`.
- The mediator MUST NOT honour `please_ack` on a `forward`.

### 3.2 Envelopes and algorithms

| | Accepted | Emitted by the mediator |
|---|---|---|
| Key agreement curves | X25519, P-256, P-384, P-521 | X25519, P-384 (its own keys, §5.2) |
| Anoncrypt | ECDH-ES+A256KW with A256CBC-HS512, A256GCM, XC20P | A256CBC-HS512 |
| Authcrypt | ECDH-1PU+A256KW with A256CBC-HS512 | same |
| Signatures | verify EdDSA (Ed25519), ES256, ES256K | EdDSA |

Accepted layerings on unpack: plaintext, signed, anoncrypt, authcrypt, anoncrypt(signed), authcrypt(signed), anoncrypt(authcrypt), anoncrypt(authcrypt(signed)). Over its transports the mediator accepts only **encrypted** envelopes (§7). It never emits anoncrypt(authcrypt(signed)).

Consistency between layers is enforced: plaintext `from` = `skid` DID = signer `kid` DID; `to`, if present, contains the DID decrypted for; the authcrypt sender key is in the sender's `keyAgreement`; the signing key is in the signer's `authentication`.

When packing, the sender key is the first `keyAgreement` key held that shares a curve with the recipient, and the message is encrypted to all the recipient's keys on that curve. A wallet whose keys are only on a curve the mediator does not hold (e.g. P-256) cannot receive authcrypted replies from it.

### 3.3 DID methods and documents

- Wallets: `did:key`, `did:peer:2`, `did:peer:4`. Mediators: `did:web` (resolved over HTTPS, cached 5 minutes).
- The Almena registry's tenants, issuers and verifiers: `did:webvh` 1.0. Their log (`did.jsonl`) is fetched over HTTPS and walked from the first entry — SCID, hash chain, `eddsa-jcs-2022` proofs by the update keys in force, pre-rotation — and believed only if every entry holds; a deactivated DID does not resolve, and a log that asks for witnesses is refused. Cached 5 minutes. They mediate like any wallet: authcrypt from their `keyAgreement` key, the `did:webvh` as mediation DID.
- `did:web` and `did:webvh` are resolved only with federation on (`ALMENA_FEDERATION`), since resolving them is outbound traffic (§6.8).
- An Ed25519 `did:key` also lists its derived X25519 key under `keyAgreement`.
- `did:peer:2` key ids are `#key-1`, `#key-2`, … in DID order; services `#service`, `#service-1`, ….
- A short-form `did:peer:4` resolves only once its long form has been seen by the same resolver.
- `DIDCommMessaging` `serviceEndpoint` is written in the v2.0 form (a list of `{uri, accept, routingKeys}`). On reading, a single object (the v2.1 form) and a legacy string endpoint are also accepted and normalised.

### 3.4 Routing

As [Routing]: `forward` messages are anoncrypted, carry the inner message as an attachment, and `next` is a DID or one of its key ids. When packing, the first `DIDCommMessaging` endpoint accepting `didcomm/v2` is used; a DID as `uri` means a mediator, whose `keyAgreement` keys go first in the routing keys. A route of more than 4 hops (that mediator included), or through the same hop twice, is refused: each hop wraps the message once more, about a third bigger each time, and the routing keys come from the recipient's DID document, i.e. from whoever made it.

A `forward` with several attachments is taken whole or not at all: they are all queued, or all routed before any is relayed; a full queue (`507`), an attachment that cannot be routed (`404`) or a destination over its relay rate (`429`, §6.7) leaves nothing behind, so the sender's retry duplicates nothing.

Not used: rewrapping, `delay_milli`.

## 4. Interpretations of and deviations from DIDComm v2.0

Where [DIDComm] is ambiguous, contradicts itself, or where Almena departs from it deliberately.

| # | Topic | [DIDComm] says | Almena |
|---|---|---|---|
| D1 | `apv` | Hash of the recipient kids. | **Enforced** on decryption: it MUST match the kids actually in the envelope. |
| D2 | ECDH-ES KDF | Prose suggests the tag is bound into the KDF. | As [RFC 7518][rfc7518]: ECDH-ES does not bind the tag; ECDH-1PU does (`SuppPubInfo` = keydatalen ‖ len(tag) ‖ tag). The spec's vectors agree. |
| D3 | anoncrypt(authcrypt(signed)) | Must not be emitted. | Accepted on unpack (the spec's own vector C.3 #6 is one); never emitted. |
| D4 | Appendix C vectors | — | Used with their errata fixed: recipient secrets written `"kid "`; C.1 made from `http://`, not `https://`; C.3 #4 is P-256, not P-521. See `crates/didcomm/tests/spec/appendix.json`. |
| D5 | Replies over HTTP | POST is one-way; replies do not come back in the response. | With `return_route` (§7.1) the reply is the HTTP response body (`200`). Without it, nothing comes back on the connection. |
| D6 | `return_route` values | `all`, `thread`, `none`. | `all` and `thread` behave alike (every reply is in the request's thread). `none` turns replies off, also on a WebSocket. |
| D7 | Live delivery | Pickup 3.0: live messages are delivered "rather than being pushed to the queue". | Live messages are queued **and** pushed; they leave the queue only with `messages-received`, so a dropped connection loses nothing. |
| D8 | `links` attachments in `forward` | Allowed. | **Refused** (`400`): fetching stranger-supplied URLs is an SSRF vector. |
| D9 | Discover Features privacy advice | Vary order, add spurious entries. | Not applied: a mediator's features are public. |
| D10 | Redirects | Only `307` followed. | Same, on every outbound request. |
| D11 | Undeliverable replies | Deliver to the sender's endpoint. | Only to a sender authenticated by authcrypt — an unauthenticated `from` could name anyone (§6.6). |
| D12 | Push protocols | Defined for DIDComm v1 only. | Used over v2 (§6.3). |

## 5. The mediator's identity

### 5.1 DID

The mediator's DID is the `did:web` of its public origin (`scheme://host[:port]`, no path), proven and fixed when it is set up (App. G) or given by `ALMENA_PUBLIC_URL`:

- `https://mediator.example.com` → `did:web:mediator.example.com`
- `http://localhost:8080` → `did:web:localhost%3A8080`

The DID document is served at `/.well-known/did.json`. A domain-based DID lets other mediators find this one without a registry.

### 5.2 Keys and DID document

| Key id | Curve | Relationships |
|---|---|---|
| `<did>#key-ed25519` | Ed25519 | `authentication`, `assertionMethod` |
| `<did>#key-x25519` | X25519 | `keyAgreement` |
| `<did>#key-p384` | P-384 | `keyAgreement` |

One service, `<did>#didcomm`, of type `DIDCommMessaging`, with two endpoints in this order:

```json
[
  { "uri": "<origin>/didcomm", "accept": ["didcomm/v2"] },
  { "uri": "wss://<host>/ws",  "accept": ["didcomm/v2"] }
]
```

(`ws://` for an `http` origin.) Push is not advertised; it is negotiated with the push protocols (§6.3).

### 5.3 Rotation

Rotation replaces all three keys at once; the DID and key ids stay. There is no overlap period: envelopes in flight to the old keys get `400` and are re-sent once the sender resolves the DID again. Queued messages are unaffected (they are encrypted to wallets, not to the mediator).

## 6. Almena extensions

What is Almena's own. Each item either adds something DIDComm does not define or fixes a behaviour DIDComm leaves to the implementation.

### 6.1 Authenticated mediation

A profile of [CoordMed] and [Pickup]:

- Every Coordinate Mediation, Message Pickup and push-protocol message MUST be **authcrypted**. Anything else gets `e.m.trust.unauthenticated`.
- A mediation is keyed by the authenticated `from` (the *mediation DID*). Nobody can read or acknowledge another wallet's queue by claiming its DID.
- `mediate-request` is granted while the mediator has room, and is idempotent: a mediation it already holds is always granted again. A new one is answered with `mediate-deny` when the mediator holds `ALMENA_MAX_MEDIATIONS` (§11), or when it is private and the request answers none of its invitations (App. G). **Almena extension:** its body says which, as `reason`: `full` or `invitation_required` (Coordinate Mediation leaves it empty; a client that does not know the field ignores it). `mediate-grant` carries `routing_did: [<mediator DID>]`; the wallet puts that DID as the `uri` of its own `DIDCommMessaging` service. **Almena extension:** it also carries `max_recipient_dids`, how many recipient DIDs the mediation may hold (`ALMENA_MAX_RECIPIENT_DIDS`, its own DID included), so the wallet can say how much room is left.
- A recipient DID belongs to the **first** mediation that registers it; later `add`s from other mediations get `client_error`. DID URLs, non-DIDs, unknown actions and going over the per-mediation limit also get `client_error`; **Almena extension:** over the limit, that entry of `updated` adds `reason: "limit"`, so the wallet can tell its user the mailbox is full rather than that something failed. Removing a DID keeps its queued messages until picked up or expired.
- `recipient-query` returns all DIDs sorted; with `paginate`, a page plus `pagination {count, offset, remaining}`.
- One queue per **mediation**, not per recipient DID, so queue ids are unique across a wallet's DIDs; `recipient_did` filters within it and MUST be one of the mediation's (`e.m.msg.unknown-recipient`).
- `delivery` carries at most `min(limit, 100)` messages, oldest first, as `base64` attachments whose `id` is the queue id to acknowledge. Messages stay queued until `messages-received`, which acknowledges at most 1000 ids at once (more: `e.m.msg.invalid-body`).
- `status` reports `message_count`, `total_bytes`, oldest/newest times, `longest_waited_seconds`, `live_delivery`.

### 6.2 Recipient possession proof

[CoordMed] has no proof that a wallet controls the DIDs it registers, so anyone could register someone else's DID first and receive (though not read) its messages. Almena closes that gap.

When `ALMENA_RECIPIENT_PROOF=required` (the default), each `recipient-update` `add` for a DID other than the mediation DID MUST carry a `proof` member:

```json
{ "recipient_did": "did:peer:2…", "action": "add", "proof": "<compact JWS>" }
```

The proof is a compact JWS ([RFC 7515][rfc7515]) whose payload is a JWT ([RFC 7519][rfc7519]) with exactly these claims:

| Claim | Value |
|---|---|
| `iss` | The DID being registered. MUST be a bare DID. |
| `aud` | The mediator's DID. |
| `sub` | The mediation DID (the authcrypt sender of the `recipient-update`). |
| `iat` | Epoch seconds of signing. |

The header `kid` MUST be a key of `iss`, and the signature MUST verify against that key in the `authentication` relationship of the resolved `iss` document. The mediator accepts `iat` no older than 5 minutes and no more than 1 minute in the future. A missing, malformed or failing proof yields `client_error` for that DID. The mediation DID itself needs no proof: its authcrypt already proves control.

Checking a proof may mean resolving `iss` over the network, so a `recipient-update` with more `add`s that need one than 100 is refused whole (`e.m.msg.invalid-body`) — a cap per message, not per mediation: a mediation holds up to `ALMENA_MAX_RECIPIENT_DIDS`, added over several updates —, and an `add` that would go over the mediation's limit is `client_error` without its proof being checked. A `recipient-update` of more than 1000 entries is refused whole too, whatever they are.

`ALMENA_RECIPIENT_PROOF=off` falls back to plain [CoordMed]. Implementation: `almena_didcomm::PossessionProof`.

### 6.3 Push protocols over DIDComm v2

The FCM ([RFC 0734][rfc0734]) and APNs ([RFC 0699][rfc0699]) protocols are used with DIDComm v2 plaintext headers and otherwise unchanged bodies:

| Protocol | PIURI | Messages |
|---|---|---|
| Push Notifications FCM 1.0 | `https://didcomm.org/push-notifications-fcm/1.0` | `set-device-info`, `get-device-info`, `device-info` |
| Push Notifications APNs 1.0 | `https://didcomm.org/push-notifications-apns/1.0` | `set-device-info`, `get-device-info`, `device-info` |

- Authcrypted and with a granted mediation, like §6.1.
- Offered only for the services the mediator is configured to push through; the others get `e.m.msg.unsupported-type`, and Discover Features discloses only the offered ones (role `notification-sender`).
- One device per service per mediation; `set-device-info` replaces it. FCM requires `device_token` and `device_platform` together; APNs a hex `device_token`. All values `null` or absent removes the device; any other shape is `e.m.msg.invalid-body`.
- `set-device-info` is answered with the [RFC 0015][rfc0015] ack, type `https://didcomm.org/notification/1.0/ack`, body `{"status": "OK"}`.
- `get-device-info` is answered with `device-info`; values are `null` when nothing is registered.

### 6.4 Wake-up notifications

A push is a hint that something is waiting, never a delivery path. Messages always remain queued until picked up.

**Payload.** Fixed and content-free: no sender, recipient DID, message id or count.

- A visible notification whose title and body are localisation **keys** into the wallet app: `almena_wake_title`, `almena_wake_body`.
- Data: `{"type": "almena.wake"}`.
- FCM (HTTP v1): high priority, `android.notification` with `title_loc_key`, `body_loc_key`, `tag` and `collapse_key` = `almena.wake`.
- APNs: `aps.alert` with `title-loc-key` / `loc-key`, `apns-push-type: alert`, priority 10, `apns-collapse-id: almena.wake`, token-based (`.p8`) provider auth.

Visible rather than silent: a woken wallet is usually locked (its keys need the PIN) and cannot pick up in the background; iOS throttles silent pushes and drops them after the user closes the app.

**When.** A message queued for a mediation that has no live session (§7.2) triggers a push to that mediation's devices, subject to coalescing:

- at most one push per mediation until the wallet next sends any Message Pickup message (including turning live mode on);
- at least `ALMENA_PUSH_MIN_INTERVAL` seconds between two pushes;
- a wallet that never picks up gets no further push until `ALMENA_QUEUE_TTL` has passed.

Tokens reported invalid are deleted (FCM `UNREGISTERED`, and `INVALID_ARGUMENT` when it is about the token — its message names the registration token or a field violation names `message.token` —, never one about the payload; APNs `410`, `BadDeviceToken`, `DeviceTokenNotForTopic`). Other failures are logged, not retried; when no device was reached the next queued message may push again after `ALMENA_PUSH_MIN_INTERVAL`, rather than only after a pickup.

**Mode.** `ALMENA_PUSH_MODE=direct`: the mediator holds the wallet app's FCM/APNs credentials and calls the services itself. A *push gateway* mode for third-party mediators (they send `{service, token}` to a gateway run by the app publisher) is reserved but not specified yet.

### 6.5 Stable mediation invitation

The mediator publishes one [Out-of-Band 2.0][didcomm] invitation that never changes, so a printed QR code keeps working:

```json
{
  "type": "https://didcomm.org/out-of-band/2.0/invitation",
  "id": "<hex of the first 16 bytes of SHA-256(mediator DID)>",
  "from": "<mediator DID>",
  "body": {
    "goal_code": "request-mediate",
    "goal": "Use this mediator for your DIDComm messages",
    "accept": ["didcomm/v2"]
  }
}
```

- No `created_time`, no attachments. The wallet resolves `from` and sends `mediate-request` with the invitation `id` as `pthid`.
- URL form: `<origin>/oob?_oob=<base64url(JSON)>`; `GET /oob` is the human-readable page that URL opens.
- Wallet form: `almena://oob?_oob=<same value>`, the wallet app's own scheme, linked from the pages for someone reading them on the phone that holds the wallet. QR codes use the `https` form, which still lands somewhere when the wallet is not installed. Wallets MUST accept both.

### 6.6 Replies without a return route

When a reply cannot go back on the connection (no `return_route`, or `none`), the mediator delivers it only if the request was authcrypted:

1. If the sender is mediated here — a registered recipient DID, or a mediation DID, registered as a recipient or not — the reply is queued for it (live push or wake-up as usual), unwrapped.
2. Otherwise it is wrapped for the sender's mediators and sent to its `DIDCommMessaging` service in the background, as a relay of §6.7 (its rate limit and retries); one over the rate is dropped.
3. A sender with no service, or whose service names this mediator without being registered here, gets nothing.

Replies to the mediator's own administrative messages are never wrapped for the wallet's mediators. Message Pickup answers (`status`, `delivery`) only travel back on the connection: queued, each would add to the queue it describes.

### 6.7 Federation without a registry

When a `forward`'s `next` is not registered here, the mediator routes the payload as a sender would: resolves `next`, wraps it for the hops of its `DIDCommMessaging` service, and POSTs it to the service URI. `ALMENA_FEDERATION=false` disables this (`404`).

- Routing (resolving `next`, wrapping) happens before the mediator answers the `forward`; sending does not. Once routed, the payloads are stored and the answer is `202`; a background worker makes the first attempt at once. No request waits on another mediator, however slowly it answers. A store that fails before they are stored is `503`.
- Before they are stored, each destination host is held to `ALMENA_RELAY_RATE_LIMIT` relays per minute (fixed window, counted in the store): over it the `forward` is `429` with `Retry-After`, and nothing is stored. Relayed replies (§6.6) count too. The per-client limit (§11) bounds each sender; this one bounds what all of them together can make the mediator send one host.
- Failed attempts are retried after 5 s, 30 s, 2 min and 10 min, then dropped. Relays survive restarts and are leased (60 s) so that no two attempts send the same one; at most 64 attempts are in flight at once, each bounded by the outbound timeout (15 s), well within its lease. At most 1000 relays wait, 50 for one destination host and 128 MiB in all; beyond that a new relay is dropped (still `202`: the sender cannot tell a relay that waits from one that will).
- A route that leads back to this mediator without a registration is `404`, not a loop.

### 6.8 Outbound request guard

Every outbound URL comes from a DID document, i.e. from strangers. Outbound HTTP (federation, `did:web`, and the onboarding's HTTPS check of a domain, whose name servers are asked only at public addresses too) MUST use `https`, MUST NOT target IP-literal hosts, and MUST NOT connect to private, loopback, link-local, CGNAT or documentation addresses — checked at connect time, so DNS rebinding cannot bypass it. A `307` is followed only to a URL that passes the same checks. A fetched DID document or `did:webvh` log weighs at most 1 MiB, a DID that failed to resolve is not fetched again for 60 s, and resolutions of one DID that miss the cache at the same time share one fetch. The cache keeps the 1000 DIDs used most recently. `ALMENA_OUTBOUND_ALLOW_INSECURE=true` lifts the guard for local multi-mediator setups only.

### 6.9 Problem codes

Problem reports follow [DIDComm] §Problem Reports: they open a child thread of the trigger (`pthid` = the trigger's `thid`) and carry `ack: [<trigger id>]`. Codes used:

| Code | Origin | When |
|---|---|---|
| `e.m.msg.unsupported-type` | Almena | Type the mediator does not handle (`args`: the type). |
| `e.m.msg.invalid-body` | Almena | Body without the shape its type requires. |
| `e.m.req.time.expired` | Almena | `expires_time` has passed. |
| `e.m.trust.unauthenticated` | Almena | Mediation, pickup or push message not authcrypted. |
| `e.m.req.no-mediation` | Almena | Pickup or push message without a granted mediation. |
| `e.m.msg.unknown-recipient` | Almena | `recipient_did` is not one of the mediation's. |
| `e.m.live-mode-not-supported` | [Pickup] | `live_delivery: true` requested over HTTP. |

"Almena" codes follow the code grammar of [DIDComm] with descriptors chosen here. Received problem reports are logged; nothing is sent back.

`forward` senders are anonymous, so `forward` failures are HTTP statuses, not problem reports (§7.1).

## 7. Transport bindings

### 7.1 HTTPS

`POST /didcomm`, `Content-Type: application/didcomm-encrypted+json` (parameters and case ignored). Plaintext and signed-only messages are refused.

| Status | Meaning |
|---|---|
| `200` | Accepted; the authcrypted reply is the body, same media type. Only when the message has `from` and `return_route` `all` or `thread`. |
| `202` | Accepted; nothing comes back on this connection. |
| `400` | Not an encrypted DIDComm message the mediator can open (bad JSON, not for the mediator, unresolvable sender, failed decryption or verification, inconsistent layers), or a malformed `forward`, or a `links` attachment. The JSON error names the category, never more. |
| `404` | `forward` to an unknown recipient (federation off, or a route back here). |
| `413` | Larger than `ALMENA_MAX_MESSAGE_BYTES`. |
| `415` | Any other `Content-Type`. |
| `429` | Over the per-client rate limit, or a `forward` to a destination over its relay rate (§6.7); with `Retry-After`. |
| `503` | Storage unavailable, also when the rate limit cannot be counted and `ALMENA_RATE_LIMIT_ON_ERROR` is `closed` (§11). |
| `507` | The recipient's queue is full (messages or bytes). |

### 7.2 WebSocket

`GET /ws` upgrades. One encrypted DIDComm message per frame (text or binary, up to `ALMENA_MAX_MESSAGE_BYTES`), both directions. `return_route` is implied on the socket. Every frame the client sends (text, binary, ping; not the pong to the mediator's ping) counts against the same per-client rate limit as `POST /didcomm`; exceeding it closes the socket with code `1008`, and a frame the rate limit cannot count while it fails closed with `1013` (try again later). At most 16 sockets per client are open at once (more: `429`), and `ALMENA_MAX_SOCKETS` in all (more: `503`, with `Retry-After`). The mediator pings every 30 s and closes a socket it has heard nothing from, not even a pong, for 90 s.

Live mode: the wallet sends an authcrypted `live-delivery-change` with `live_delivery: true` and is answered with `status` (`live_delivery: true`). From then on, each message queued for the mediation is pushed as a `delivery` with one attachment whose `id` is the queue id. Messages queued earlier are fetched with `delivery-request`. Live mode ends with the connection. A mediation is *online* while it has a live session (Appendix E); online mediations get no push.

### 7.3 Other endpoints

| Endpoint | Content |
|---|---|
| `GET /.well-known/did.json` | The mediator's DID document (§5.2). |
| `GET /.well-known/security.txt` | Where to report a vulnerability (RFC 9116). |
| `GET /oob/invitation` | The invitation (§6.5) and its URL form, as JSON. |
| `GET /oob` | Human-readable invitation page. |
| `GET /health` | Status, version and DID; `503` while storage is down. `capacity` is `full` while new mediations are denied (§11). |
| `GET /`, `GET /icon.png`, `GET /fonts/{name}` | Home page: status, DID, invitation QR and `almena://` link (a private mediator's offers none); its icon and typefaces. |
| `GET /setup`, `POST /setup`, `GET /.well-known/almena-setup` | The onboarding and the first administrator (App. G). |
| `/portal/…` | The administration portal (App. G). |
| `GET /openapi.json`, `GET /docs` | API reference. |

TLS is terminated by a reverse proxy; the mediator speaks plain HTTP.

## 8. Discover Features disclosure

`disclose` answers with the features matching the queries (`*` is a wildcard; unknown feature types match nothing). Matching takes time linear in the pattern however many `*` it holds; a pattern over 256 characters matches nothing, and more than 32 queries in one message are `e.m.msg.invalid-body`:

- `protocol`: every PIURI of §9 the mediator offers, with roles where they apply (`receiver`, `responder`, `mediator`, `notification-sender`);
- `header`: `return_route`;
- `constraint`: `max_receive_bytes` = `ALMENA_MAX_MESSAGE_BYTES`.

## 9. Protocols

| Protocol | PIURI | Defined in | Almena changes |
|---|---|---|---|
| Trust Ping 2.0 | `https://didcomm.org/trust-ping/2.0` | [DIDComm] | None; `ping-response` unless `response_requested: false`. |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0` | [DIDComm] | §8, D9. |
| Report Problem 2.0 | `https://didcomm.org/report-problem/2.0` | [DIDComm] | §6.9. |
| `return_route` | header | [ReturnRoute] | D5, D6. |
| Coordinate Mediation 3.0 | `https://didcomm.org/coordinate-mediation/3.0` | [CoordMed] | §6.1, §6.2. |
| Routing 2.0 | `https://didcomm.org/routing/2.0` | [Routing] | D8, §6.7. |
| Message Pickup 3.0 | `https://didcomm.org/messagepickup/3.0` | [Pickup] | §6.1, D7, §7.2. |
| Out-of-Band 2.0 | `https://didcomm.org/out-of-band/2.0` | [DIDComm] | §6.5. |
| Push Notifications FCM 1.0 | `https://didcomm.org/push-notifications-fcm/1.0` | [FCM] | §6.3. |
| Push Notifications APNs 1.0 | `https://didcomm.org/push-notifications-apns/1.0` | [APNs] | §6.3. |
| ACK (notification) 1.0 | `https://didcomm.org/notification/1.0` | [Ack] | Emitted only, as the answer to `set-device-info`. |

## 10. Conformance evidence

- All nine vectors of [DIDComm] Appendix C (3 signed, 6 encrypted) pass at the JWS/JWE level and through full unpack (errata: D4). The spec's `did:key`, `did:peer:2` and `did:peer:4` examples are unit tests.
- Interoperability, both directions (`crates/interop`):
  - **didcomm-rust** 0.4: anoncrypt (A256CBC-HS512, A256GCM, XC20P) and authcrypt on X25519 and P-256, sender protection, Ed25519/P-256/secp256k1 signatures, plaintext, `forward` through the mediator.
  - **affinidi-messaging-didcomm** 0.15: anoncrypt and authcrypt on X25519, P-256, P-384, P-521, the three signature algorithms, and a full mediation run (ping, mediation, `forward`, pickup, acknowledgement) on X25519 and P-384.
  - **Veramo** 7.0.1 does **not** interoperate: its JWEs lack `apv` (and `apu` in authcrypt), and its authcrypt uses ECDH-1PU v3 defaulting to A256GCM, all outside DIDComm v2.0. The mediator answers `400`.
- Note: `anonymous_sender` in Almena's unpack metadata means "no authcrypt layer"; didcomm-rust also sets it when the sender is protected.

## 11. Limits

Limits are operator settings, not protocol: a public mediator takes any wallet, a private one only the wallets it invited (§6.1, App. G), over the same protocol.

A mediator's physical resources are bounded, so besides the limits per mediation and per client it has ceilings in all. At a ceiling, what the mediator already holds keeps working (pickup, acknowledgement, recipient updates, a repeated `mediate-request`) and only what would add load is refused: new mediations (`mediate-deny`), new WebSockets (`503`). The per-mediation quotas, times `ALMENA_MAX_MEDIATIONS`, bound the database's size. Defaults:

| Setting | Default | Effect |
|---|---|---|
| `ALMENA_MAX_MESSAGE_BYTES` | 1 MiB | `413`; disclosed as `max_receive_bytes`. |
| `ALMENA_QUEUE_TTL` | 30 days | Undelivered messages dropped. |
| `ALMENA_QUEUE_MAX_MESSAGES` | 1 000 per mediation | `507`. |
| `ALMENA_QUEUE_MAX_BYTES` | 10 MiB per mediation | `507`. |
| `ALMENA_MAX_RECIPIENT_DIDS` | 1000 per mediation (a wallet's inbox, its card and one per contact) | `client_error`. |
| `ALMENA_MAX_MEDIATIONS` | 10 000 in all; 0 = no limit | A new mediation gets `mediate-deny`. |
| `ALMENA_MAX_SOCKETS` | 5 000 WebSockets in all | `503` with `Retry-After`. |
| `ALMENA_MEDIATION_TTL` | 90 days | A mediation with no authenticated mediation, pickup or push message for this long is removed, with its DIDs, queue and devices. |
| `ALMENA_RATE_LIMIT` | 60 / min / client | `429`, or WebSocket close `1008`. A client is an IPv4 address or an IPv6 /64: the TCP peer, or the address a trusted proxy names (App. G). |
| `ALMENA_RATE_LIMIT_ON_ERROR` | `closed` | When the store cannot count a message: `closed` refuses it (`503`, WebSocket close `1013`), `open` lets it through. Either way it is logged and counted (App. H). |
| `ALMENA_RELAY_RATE_LIMIT` | 600 / min / destination host; 0 = no limit | `429` on a `forward` to be relayed (§6.7). |
| `ALMENA_PUSH_MIN_INTERVAL` | 60 s | §6.4. |

The full list is in [.env.example](.env.example).

## 12. Security and privacy considerations

- **Content.** The mediator stores and forwards opaque envelopes encrypted to wallets. It learns recipient DIDs, sizes and timing, not content or senders of forwarded messages.
- **Queue ownership.** Authcrypt on every administrative message (§6.1) and possession proofs (§6.2) bind queues to wallets that control the DIDs.
- **Push.** Payloads carry nothing linkable to a DID, a sender or a message (§6.4). Push providers learn only that a device is being woken.
- **Metrics.** Aggregate only — no DIDs, nothing per mediation — and served on a separate listener.
- **Outbound requests.** Guarded against SSRF (§6.8); `links` attachments refused (D8). Relays are sent in the background and held to a rate per destination host (§6.7), so the mediator is neither held up by nor turned against another host.
- **Client addresses.** A proxy's client IP header is believed only from a trusted proxy's address (App. G); anyone else is counted by its own.
- **Keys.** The mediator's private keys are its identity; rotation is immediate (§5.3).
- **Mediation DIDs.** A mediation's own DID is never another mediation's recipient, proof or not, and replies to it wait in its own queue (§6.6), where its wallet may name it as `recipient_did`.
- **Strangers' DIDs.** Unpacking resolves the DIDs a sender names (`skid`, a JWS `kid`, `from_prior`'s `iss`) before anything is proven, which for `did:web` / `did:webvh` is a fetch to a host the sender chose; it is bounded by the rate limit per client, the cache (failures included) and the guard of §6.8. Base58 text over 8 KiB is not decoded (its cost grows with the square of its length), and the long forms of `did:peer:4` are remembered only once they resolve, the oldest forgotten first.
- **Push tokens.** A device token is not bound to the wallet that registers it, as in the push protocols themselves: whoever learns one can have it woken, at most once per `ALMENA_PUSH_MIN_INTERVAL` per mediation that registers it. The notification carries nothing (§6.4).
- **Signatures.** `ES256` signatures are taken with either form of S, as JOSE allows and other DIDComm libraries write; nothing is told apart by a JWS's bytes, only by the message `id`.
- **Rotations.** A `from_prior` whose `exp` has passed or whose `nbf` has not come (5 minutes of clock difference allowed) is refused.
- **The portal.** The setup code never travels in a URL (forms post it), so access logs and browser histories do not keep it. An administrator's invitation is a link, good once and for 7 days, for whoever opens it with a wallet: it is handed only to the person invited. Signing in by QR code proves who answered, not which browser shows the code: an administrator approves only a request they opened themselves.

## 13. Not specified / not implemented

- DIDComm v1 envelopes; DIDComm v2.1 features beyond what §3.3 accepts on read.
- `forward` rewrapping, `delay_milli`, `links` attachments.
- A push gateway for third-party mediators (§6.4).
- Several instances of one mediator: it runs as one process on one SQLite file (App. E).
- Message content protocols, groups, directories, a mediator registry.

---

# Appendices (non-normative)

How this implementation meets the specification, and why. Nothing here binds another implementation.

## Appendix A. Decisions

Items were either **decided** explicitly or are **proposed** defaults that stand until someone changes them. The main decisions and where they are specified:

| Decision | Why | Where |
|---|---|---|
| DIDComm **v2.0**, not v2.1 | v2.0 is DIF-ratified; v2.1 only Working Group Approved. | §2 |
| **Pure mediator** | Wallets encrypt end to end; the mediator only handles envelopes. | §1 |
| **Own DIDComm implementation**, in this workspace | No JOSE or DIDComm dependency to trust or wait for; the wallet can reuse it. | App. B |
| **Authcrypt** on mediation, pickup and push | Queues keyed by an authenticated DID; nobody claims another's. | §6.1 |
| **Recipient possession proof** | Coordinate Mediation lets anyone register someone else's DID first. | §6.2 |
| **Open with limits** | Any wallet may mediate on a public mediator, bounded by quotas. | §11 |
| **Public or private**, fixed at setup | A private mediator serves only invited wallets, by Out-of-Band invitations with uses and days; changing the mode would strand its wallets, so a mediator of the other mode is another mediator. (2026-11-11) | §6.1, App. G |
| **Onboarding with a domain proof** | The URL becomes the `did:web`, so it is proven (TXT and HTTPS) before it is taken, and never set in `.env`. (2026-11-11) | App. G |
| **Administrators sign in with the wallet**, all equal | No passwords to keep; the key is derived per origin, so an administrator is unlinkable across sites. The first one claims the mediator with the setup code. (2026-11-11) | App. G |
| **The administration in its own SQLite** | Site, administrators and sessions apart from the queues. (2026-11-11) | App. D |
| **The setup code never in a URL**; QR codes renewed until read | Logs and histories keep URLs; a code on a screen should not outlive its minute. (2026-11-12) | §12, App. G |
| **Ceilings in all**, refusing only what is new | Resources are physical; past a ceiling the wallets already served keep working, and pickups free the room. (2026-10-13) | §6.1, §11 |
| **`links` attachments refused** | SSRF and downloading on strangers' behalf; no tested client uses them. | D8 |
| **Live messages stay queued** until acknowledged | Mobile connections drop mid-delivery. | D7 |
| **Visible, content-free pushes** | Locked wallets cannot pick up in the background; iOS throttles silent pushes. (2026-09-24) | §6.4 |
| **Direct push mode** | Every mediator is run by the wallet's publisher for now. | §6.4 |
| **Stable invitation** | A printed QR code keeps working. | §6.5 |
| **No mediator registry** | `did:web` makes mediators discoverable by domain. | §6.7 |
| **Relay retries survive restarts** | A crash must not lose a relay. | §6.7, App. D |
| **Immediate key rotation**, no overlap | Rotation is mainly for a compromised key, which must stop working at once. | §5.3 |
| **SQLite**, one file | Queues survive restarts; nothing to run beside the mediator. Redis until 2026-11-10. | App. D |
| **One queue per mediation** | Queue ids unique across a wallet's DIDs. | §6.1 |
| **Relays sent in the background**, rate-limited per destination | A `forward` from anyone must not hold a request handler on a stranger's server, nor make the mediator flood one host. (2026-11-01) | §6.7 |
| **Client IP header from trusted proxies only**; the rate limit fails closed | A header anyone can write is no address; an uncountable request is not let through by default. (2026-11-01) | §11, App. G |
| **Metrics on their own listener**, aggregate only | Never exposed through the public proxy; no DIDs. | App. H |

## Appendix B. Code layout and library

A Cargo workspace:

```
mediator/
├── crates/
│   ├── didcomm/    almena-didcomm  — message format, envelopes, crypto, DID resolution
│   ├── mediator/   almena-mediator — the service
│   └── interop/    almena-interop  — interoperability tests only
├── interop/veramo/ Veramo client against a running mediator
├── Dockerfile
└── compose.yml
```

`almena-didcomm` knows nothing about HTTP, storage or mediation, so the wallet depends on it (a git dependency pinned to a commit: a change here reaches the wallet when it moves the pin); if that becomes awkward it is extracted into its own project.

- Built on RustCrypto primitives (`x25519-dalek`, `ed25519-dalek`, `p256`, `p384`, `p521`, `k256`, `aes-kw`, `aes-gcm`, `chacha20poly1305`, `aes` + `cbc` + `hmac` + `sha2`). The Concat KDF is a few lines of our own (the `concat-kdf` crate lags behind `sha2`).
- DID resolution is a trait, so the mediator can add caching and the wallet can plug in its own. `LocalResolver` handles `did:key` and `did:peer`; `did::webvh` walks a `did:webvh` log the caller fetched (the mediator's `WebResolver` fetches it, and `did:web` documents); `StaticResolver` holds fixed documents; `ChainResolver` combines them. `LocalResolver` keeps the `did:peer:4` long-form mapping in memory (bounded); the wallet will need to persist it.
- `pack_encrypted` wraps the message in `forward`s for the recipient's hops (`PackOptions::forward`, on by default) and returns the URI to POST to (`PackedMessage::service_uri`). `almena_didcomm::route` does the same for a payload the mediator relays.
- `PossessionProof` makes and checks the proofs of §6.2.

## Appendix C. Mediator keys

The three keys of §5.2 are generated on first start and kept in `ALMENA_KEYS_PATH` (default `data/keys.json`; `/data/keys.json` in the container, on the `mediator-data` volume) as JSON with the three private JWKs, mode `0600`. Mounting a file there brings your own keys. `almena-mediator rotate-keys` (`task rotate-keys` under Docker, which also restarts the container) writes new ones; they take effect on the next start. Other mediators cache the DID document for 5 minutes. The mediator resolves its own DID from memory.

## Appendix D. Storage

SQLite, one file at `ALMENA_DB_PATH` (default `data/mediator.db`; `/data/mediator.db` in the container, on the `mediator-data` volume beside the keys), created with its directory on first start, in WAL mode with `synchronous = NORMAL`. The mediator refuses to start without it, and `/health` answers `503` while it cannot be read. `ALMENA_DB_PATH=:memory:` keeps everything in the process, for development and the tests.

- Storage sits behind a `Store` trait (`crates/mediator/src/store/`), implemented once (`sqlite.rs`, on `rusqlite` with SQLite bundled). A contract test pins its behaviour. Every call is one transaction, run on Tokio's blocking pool over one connection, so each operation is atomic.

| Table | Holds |
|---|---|
| `mediations` | Each mediation and its last wallet activity, for `ALMENA_MEDIATION_TTL` |
| `recipients` | Recipient DID → the mediation that registered it |
| `messages` | The queues: mediation, recipient, time received, the message; `seq` orders them |
| `devices` | Per mediation, push service (`fcm`, `apns`) → token and platform |
| `push_sent` | Time of the last push, and until when it holds the next |
| `relays` | Relays waiting: when due (or leased until), URI, destination host, message, attempts |
| `hits` | Rate-limit counters (fixed window): `didcomm:{client}`, `relay:{host}` |

The administration — the site, the administrators, their sessions and invitations, a private mediator's members — is another SQLite file, `ALMENA_ADMIN_DB_PATH` (default `data/admin.db`), with the tables `settings`, `admins`, `sessions`, `invitations` and `members` (`crates/mediator/src/admin.rs`). Removing a member also removes its mediation from the main store.

A queue id is `<received ms>-<seq>`. Expired messages are deleted on every read and write of their queue; idle mediations are swept hourly with everything they own. A background worker takes due relays as soon as one is stored, and every second, and leases them for 60 s. `PRAGMA user_version` numbers each schema (1); until production a schema changes in place, without migrations.

## Appendix E. One instance

The mediator is one process: live sessions are held by the process that holds their socket (`dispatch/live.rs`), and a mediation is online when one of them is live (§6.4). Running several instances on one database is not supported; until 2026-11-10 they shared live delivery over Redis pub/sub.

## Appendix F. Push gateway (planned)

Sending a push needs the credentials of the app that owns the token, which belong to the wallet's publisher. Today every mediator is run by the publisher (`ALMENA_PUSH_MODE=direct`). When third parties run mediators, they will instead send `{service, token}` to a gateway run by the publisher; nothing it sees is linked to a DID or to message content. Desktop wallets have no push: they receive over WebSocket while running and poll on start.

## Appendix G. Deployment and configuration

The mediator speaks plain HTTP; TLS is terminated by a reverse proxy that whoever runs it chooses and configures — this project ships none. The first public mediator is `https://mediator.almena.id` (`did:web:mediator.almena.id`), set up through the onboarding below and administered since 2026-11-12. Development may use the same name, pointed at the developer's machine in `/etc/hosts` and served by the platform's development proxy (`../develop`). The domain is not fixed anywhere: the onboarding asks for it (below).

**Setup.** A mediator starts unconfigured. It writes a one-time setup code to its log (`almena-mediator setup` prints a new one; only its SHA-256 is kept) and serves only its onboarding, with `/health` at `200`, status `setup`, so that a proxy waiting on it starts. With the code, `/setup` asks for the public URL — `https://` and a domain, nothing after it — and the mode: **public** (any wallet may hold a mailbox) or **private** (only the wallets its administrators invite; Coordinate Mediation answers anyone else `mediate-deny`). The URL is proven before it is taken: a TXT record at `_almena-mediator.<host>` holding the value the page shows — HMAC-SHA256 of the host under a secret this mediator made once and keeps, so it is the same every time for the same domain at the same mediator and nobody else can work it out — (control of the domain; asked of the zone's own name servers first, without recursion or cache — found through 1.1.1.1 and 8.8.8.8 —, then of those public resolvers, then of the system's, so a resolver that cached "no such name" before the record existed does not hide it), and `GET https://<host>/.well-known/almena-setup` answering the same value (the domain, its proxy and certificate reach this mediator, which `did:web` needs). With both, the URL and the mode are written to the administration's own SQLite (`ALMENA_ADMIN_DB_PATH`) and the mediator starts in full on the same port; the page waits for it to answer and goes on by itself to becoming its first administrator at the public URL (the code posted again, never in a URL); until it has an administrator, its home (`/`) leads to `/setup`. The mode never changes: a mediator with the other mode is another mediator, and one whose `ALMENA_ACCESS` contradicts what it was set up as refuses to start. `ALMENA_PUBLIC_URL`, with `ALMENA_ACCESS`, sets it up without the proof for development and tests, and pins the URL to the variable; a deployment does not set it.

**Moving the URL.** An administrator may move the mediator to another URL from the portal's site page, unless `ALMENA_PUBLIC_URL` pins it. The new domain is proven as at setup (the same TXT label and well-known path; the value is the domain's at this mediator, the same as ever for that domain, served by the running mediator while the move is under way). With both proofs the URL is written and the mediator restarts in the same process as the new `did:web` (on Windows, which cannot replace a running program, as a child the old process waits for). Its DID changes, so every wallet connects again, and relationships through it stop until their wallets move them; a private mediator's members need new invitations. The wallet signs in with a key derived from the origin, so no administrator is recognised at the new address: each is turned into an invitation to be one again there (one use, 7 days), the administrators and their sessions are removed, and the one who moved it is shown theirs. No setup code is written to the log after such a move, so nobody reading it can claim the mediator before its administrators are back; only once their invitations are spent or expired with nobody there is one written again, at the next start. Changing `ALMENA_PUBLIC_URL` moves it the same way at the next start, with nobody to show an invitation to: the setup code is written to the log again.

**Administrators.** Once set up, `<url>/setup` with the same code shows a sign-in request for the Almena wallet, and the wallet that answers first becomes the first administrator (checked and written in one step, so two answering at once cannot both be); the code then stops working. Administrators sign in at `/portal` the same way. The sign-in is the registry's (SIOPv2, `direct_post`): `almena://auth?request_uri=<url>/portal/requests/<id>`, a request (`purpose: sign_in`, `client_id` the public URL, a nonce) answered with an `id_token` — a compact JWS, `EdDSA`, by an Ed25519 `did:key` that is both its `iss` and `sub`, `aud` the public URL, the request's `nonce`, `iat` within 5 minutes. The wallet derives that key from the origin it reads the request from, so an administrator is one DID at this mediator and none other can link it. The page showing a request swaps it for a new one every minute while no wallet has read it (`POST /portal/sign-in/renew`, with a new cookie); one a wallet read stays until it is answered or expires. Requests last 5 minutes, 1000 at most wait at once and 5 from one client (an IPv4 address or an IPv6 /64, as the rate limit counts them), so nobody can keep everyone else from signing in; the browser that asked collects the answer with a secret only it holds (a cookie). A session is a cookie whose SHA-256 the administration database keeps, ended after 12 h unused, by signing out, or when its holder stops being an administrator.

**Invitations.** Administrators are all equal: any of them invites another — a link to `/portal/join/<id>`, one use, 7 days, taken by signing in there with the wallet — and removes any, itself included (without any, the next start writes a new setup code). A private mediator takes a new wallet only by invitation. An administrator makes one with a label, a number of uses (1–1000) and of days (1–90); it is the mediator's own Out-of-Band invitation (§6.5) with the invitation's id as its `id`, shown as a QR code and an `https://<host>/oob?_oob=…` link (the page there opens that same invitation in the wallet). The wallet answers it as Out-of-Band 2.0 has it: its `mediate-request` carries the invitation's id as `pthid`. A new mediation takes one use (given back if the mediator is full); one already held needs no invitation, so the wallet's repeated `mediate-request`s go without it. The mediator records each member with the invitation's label; removing a member deletes its mediation with everything it owns. A private mediator's home and `/oob` pages offer no invitation of their own.

Settings beyond §11, all `ALMENA_*` environment variables (full list in [.env.example](.env.example)):

| Variable | Default | Meaning |
|---|---|---|
| `ALMENA_PUBLIC_URL` | — | Development and tests: the public origin (§5.1) without the onboarding. Unset — always, in a deployment — the onboarding asks for it and proves it. |
| `ALMENA_ACCESS` | `public` | `public` or `private`, with `ALMENA_PUBLIC_URL`; otherwise the onboarding asks. |
| `ALMENA_ADMIN_DB_PATH` | `data/admin.db` | The administration's SQLite: the site, the administrators, the setup code. |
| `ALMENA_KEYS_PATH` | `data/keys.json` | Mediator keys (App. C). |
| `ALMENA_DB_PATH` | `data/mediator.db` | The SQLite database (App. D); `:memory:` keeps it in the process. |
| `ALMENA_RECIPIENT_PROOF` | `required` | §6.2. |
| `ALMENA_FEDERATION` | `true` | §6.7. |
| `ALMENA_OUTBOUND_ALLOW_INSECURE` | `false` | §6.8. |
| `ALMENA_CLIENT_IP_HEADER` | — | Behind a proxy: header with the client IP; its **last** value is used, and only when the TCP peer is a trusted proxy. Unset, missing from a request, or sent by anyone else: the TCP peer. |
| `ALMENA_TRUSTED_PROXIES` | loopback and private ranges | Comma-separated CIDRs (`127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7`): the peers whose client IP header is believed. Empty: none. |
| `ALMENA_PUSH_MODE` | `off` | `off` or `direct`. |
| `ALMENA_FCM_SERVICE_ACCOUNT` | — | Service account key (JSON) of the wallet app's Firebase project. |
| `ALMENA_APNS_KEY_PATH`, `ALMENA_APNS_KEY_ID`, `ALMENA_APNS_TEAM_ID`, `ALMENA_APNS_TOPIC` | — | APNs `.p8` key, its id, the team id and the app's bundle id; all four or none. |
| `ALMENA_APNS_SANDBOX` | `false` | Push to the APNs sandbox. |
| `ALMENA_METRICS_ADDR` | — | Metrics listener (App. H); off when unset. |

On `SIGTERM` the mediator stops taking connections, closes its WebSockets (`1001`) and gives requests in flight 20 s to finish before it stops anyway; Compose waits 30 s (`stop_grace_period`) before killing it.

Under Compose the mediator's port is published on loopback only (`ALMENA_MEDIATOR_BIND`): the way in is the operator's proxy, which should set a client IP header (`ALMENA_CLIENT_IP_HEADER`, e.g. `x-forwarded-for`) and reaches the mediator from loopback or a private range, trusted by default. A client that reaches the mediator from a public address is counted by that address whatever header it writes; with the port published on every interface, narrow `ALMENA_TRUSTED_PROXIES` to the proxy's network (Docker's port publishing can make outside clients appear from the bridge gateway).

## Appendix H. Metrics

Prometheus text format on `ALMENA_METRICS_ADDR`, hand-written counters. Aggregate only:

| Metric | Labels |
|---|---|
| `almena_mediator_info` | `version` |
| `almena_didcomm_messages_total` | `transport` (`http`, `websocket`), `outcome` (`accepted`, `reply`, `rejected`) |
| `almena_rate_limited_total` | — |
| `almena_rate_limit_failures_total` | `result` (`allowed`, `refused`): rate-limit checks the store failed, and what `ALMENA_RATE_LIMIT_ON_ERROR` made of them |
| `almena_relay_rate_limited_total` | — (forwards refused by `ALMENA_RELAY_RATE_LIMIT`) |
| `almena_forwards_total` | `result` (`queued`; `relayed` on the first attempt; `relay_scheduled`, first attempt failed and retried; `relay_dropped`, too many relays waiting; `refused`) |
| `almena_relay_retries_total` | `result` (`delivered`, `rescheduled`, `abandoned`): attempts after the first |
| `almena_pushes_total` | `service` (`fcm`, `apns`), `result` (`delivered`, `invalid_token`, `failed`) |
| `almena_didcomm_message_seconds` (histogram) | — (time from envelope to answer) |
| `almena_websocket_connections` (gauge) | — |
| `almena_live_sessions` (gauge) | — (WebSockets in live mode) |
| `almena_messages_acknowledged_total` | — (with `almena_forwards_total{result="queued"}`, how the queues grow) |
| `almena_store_errors_total` | — |
| `almena_mediations_granted_total`, `almena_mediations_removed_total` | — |
| `almena_capacity_refused_total` | `reason` (`mediations`, `websockets`): what was refused at a ceiling (§11) |
| `almena_mediations` (gauge) | — (mediations held, sampled every 5 s) |


## Appendix I. Phases

1. ✅ **`almena-didcomm`** — message model, keys, `did:key` / `did:peer`, JWS, anoncrypt and authcrypt, pack/unpack with consistency checks and `from_prior`, spec test vectors.
2. ✅ **Mediator skeleton** — identity and keys, `did:web` document, `POST /didcomm`, storage (Redis, SQLite since 2026-11-10), Trust Ping, Discover Features, Report Problem, `return_route`.
3. ✅ **Mediation** — Coordinate Mediation 3.0, `forward`, Message Pickup 3.0 (polling), limits.
4. ✅ **Live and network** — WebSocket and live delivery, Out-of-Band invitations, federation.
5. ✅ **Push** — FCM and APNs protocols, token storage, coalesced wake-ups, direct mode. The push gateway (App. F) waits for third-party mediators.
6. ~~**Calls**~~ — TURN credentials and call rings, built 2026-10-03 and removed 2026-11-10 with calls in the wallet.
7. ✅ **Hardening and scaling** — relays sent in the background with a rate per destination (§6.7), the client IP header believed from trusted proxies only and the rate limit failing closed (§11, App. G), an LRU cache for `did:web` / `did:webvh` with concurrent misses coalesced and, until 2026-11-10, live delivery across instances on Redis.
8. ✅ **Administration** (2026-11-11 – 2026-11-12) — the onboarding with its domain proof, public and private mediators, administrators signing in with the wallet, the dashboard (overview, mailboxes, members, administrators, site and moving the URL), invitations; then a review: linear Discover Features matching, bounded routes, sign-in requests per client, an atomic first claim, the setup code kept out of URLs, renewed QR codes (App. G).

Each phase ends with `task check` green and this document updated.

[didcomm]: https://identity.foundation/didcomm-messaging/spec/v2.0/
[did]: https://www.w3.org/TR/did-core/
[didkey]: https://w3c-ccg.github.io/did-method-key/
[didpeer]: https://identity.foundation/peer-did-method-spec/
[didweb]: https://w3c-ccg.github.io/did-method-web/
[didwebvh]: https://identity.foundation/didwebvh/v1.0/
[rfc2119]: https://www.rfc-editor.org/rfc/rfc2119
[rfc8174]: https://www.rfc-editor.org/rfc/rfc8174
[rfc7515]: https://www.rfc-editor.org/rfc/rfc7515
[rfc7516]: https://www.rfc-editor.org/rfc/rfc7516
[rfc7517]: https://www.rfc-editor.org/rfc/rfc7517
[rfc7518]: https://www.rfc-editor.org/rfc/rfc7518
[rfc7519]: https://www.rfc-editor.org/rfc/rfc7519
[rfc8037]: https://www.rfc-editor.org/rfc/rfc8037
[ecdh1pu]: https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04
[xc20p]: https://datatracker.ietf.org/doc/html/draft-amringer-jose-chacha
[coordmed]: https://didcomm.org/coordinate-mediation/3.0/
[routing]: https://identity.foundation/didcomm-messaging/spec/v2.0/#routing-protocol-20
[pickup]: https://didcomm.org/messagepickup/3.0/
[rfc0092]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0092-transport-return-route
[rfc0734]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0734-push-notifications-fcm
[rfc0699]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0699-push-notifications-apns
[rfc0015]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0015-acks
[fcmapi]: https://firebase.google.com/docs/reference/fcm/rest/v1/projects.messages
[apnsapi]: https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns
[sicpa]: https://github.com/sicpa-dlab/didcomm-rust
[affinidi]: https://github.com/affinidi/affinidi-tdk-rs
[veramo]: https://veramo.io
[rustcrypto]: https://github.com/RustCrypto
