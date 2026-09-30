# Almena Mediator Specification

Version: draft 1 (2026-09-25) · Status: describes `almena-mediator` as implemented (phases 1–6, Appendix I).

This document specifies the Almena Mediator as a profile of, and a set of extensions to, [DIDComm Messaging v2.0][didcomm]. It does not restate DIDComm: wherever a behaviour is the one the referenced specification defines, it says so and points at it. What it does spell out is what Almena adds, restricts, interprets or leaves out.

Sections 1–13 are the contract: what a wallet, another mediator or another implementation can rely on. The appendices (non-normative) record how `almena-mediator` implements it and why each decision was taken. Read this document before DIDComm work and keep it current with every change.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in [RFC 2119][rfc2119] and [RFC 8174][rfc8174].

## 1. Scope

The Almena Mediator is a **pure mediator**: a mailbox that accepts DIDComm encrypted envelopes for the wallets it serves, queues them while those wallets are offline, and hands them over when they connect. It also relays envelopes for wallets mediated elsewhere, wakes mobile wallets with content-free push notifications, and gives its wallets credentials for a TURN relay so that their calls can be relayed.

- It MUST NOT decrypt messages addressed to anyone but itself. The only messages it opens are the administrative ones wallets send *to the mediator* (mediation, pickup, device registration, TURN credentials, ping, feature discovery).
- Out of scope: message content and wallet-to-wallet protocols (Basic Message, chat, call signalling), the media of calls, groups, user directories, a registry of mediators.

## 2. Sources

### 2.1 Normative

| Ref | Document | Used for |
|---|---|---|
| [DIDComm] | [DIF DIDComm Messaging v2.0][didcomm] (DIF-ratified) | Message format, envelopes, algorithms, routing, transports, Trust Ping, Discover Features, Report Problem, Out-of-Band. **v2.0, not v2.1** (v2.1 is only Working Group Approved). |
| [DID] | [W3C Decentralized Identifiers v1.0][did] | DIDs, DID documents, resolution. |
| [did:key] | [did:key Method][didkey] | Wallet and test DIDs. |
| [did:peer] | [Peer DID Method][didpeer] (numalgo 2 and 4) | Pairwise wallet DIDs. |
| [did:web] | [did:web Method][didweb] | Mediator DIDs. |
| [JOSE] | [RFC 7515][rfc7515] (JWS), [RFC 7516][rfc7516] (JWE), [RFC 7517][rfc7517] (JWK), [RFC 7518][rfc7518] (JWA), [RFC 7519][rfc7519] (JWT), [RFC 8037][rfc8037] (OKP) | Envelopes, keys, possession proofs. |
| [1PU] | [ECDH-1PU, draft-madden-jose-ecdh-1pu-04][ecdh1pu] | Authcrypt key agreement, as DIDComm v2.0 profiles it. |
| [XC20P] | [draft-amringer-jose-chacha][xc20p] | Optional content encryption. |
| [CoordMed] | [Coordinate Mediation 3.0][coordmed] | Mediation. |
| [Routing] | [Routing 2.0][routing] (DIDComm §Routing) | `forward`. |
| [Pickup] | [Message Pickup 3.0][pickup] | Polling and live delivery. |
| [ReturnRoute] | [Aries RFC 0092 Transports Return Route][rfc0092], as carried into DIDComm v2 | `return_route` header. |
| [FCM] | [Aries RFC 0734 Push Notifications FCM][rfc0734] | Device registration, FCM. Written for DIDComm v1; adapted in §6.2. |
| [APNs] | [Aries RFC 0699 Push Notifications APNs][rfc0699] | Device registration, APNs. Written for DIDComm v1; adapted in §6.2. |
| [Ack] | [Aries RFC 0015 ACKs][rfc0015] | The `ack` the push protocols answer with. |
| [TURN] | [RFC 8656][rfc8656], Traversal Using Relays around NAT | The relay the credentials of §6.9 are for. |
| [TURN-REST] | [A REST API for Access to TURN Services, draft-uberti-behave-turn-rest-00][turnrest] | The form of those credentials (§6.9). An expired Internet-Draft, but the mechanism TURN servers implement (coturn's `use-auth-secret`). |

### 2.2 Informative

- [Firebase Cloud Messaging HTTP v1 API][fcmapi] and [Apple Push Notification service][apnsapi] — the push back-ends.
- [WebRTC: Real-Time Communication in Browsers][webrtc] (W3C Recommendation) — the API wallets place calls with; the credentials of §6.9 have the shape of its `RTCIceServer`. The calls themselves are wallet to wallet and not specified here.
- [coturn][coturn] — the TURN server `compose.yml` runs.
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
- An Ed25519 `did:key` also lists its derived X25519 key under `keyAgreement`.
- `did:peer:2` key ids are `#key-1`, `#key-2`, … in DID order; services `#service`, `#service-1`, ….
- A short-form `did:peer:4` resolves only once its long form has been seen by the same resolver.
- `DIDCommMessaging` `serviceEndpoint` is written in the v2.0 form (a list of `{uri, accept, routingKeys}`). On reading, a single object (the v2.1 form) and a legacy string endpoint are also accepted and normalised.

### 3.4 Routing

As [Routing]: `forward` messages are anoncrypted, carry the inner message as an attachment, and `next` is a DID or one of its key ids. When packing, the first `DIDCommMessaging` endpoint accepting `didcomm/v2` is used; a DID as `uri` means a mediator, whose `keyAgreement` keys go first in the routing keys.

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
| D12 | Push protocols | Defined for DIDComm v1 only. | Used over v2 (§6.2). |

## 5. The mediator's identity

### 5.1 DID

The mediator's DID is the `did:web` of its public origin (`ALMENA_PUBLIC_URL`, `scheme://host[:port]`, no path):

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

(`ws://` for an `http` origin.) Push is not advertised; it is negotiated with the push protocols (§6.2).

### 5.3 Rotation

Rotation replaces all three keys at once; the DID and key ids stay. There is no overlap period: envelopes in flight to the old keys get `400` and are re-sent once the sender resolves the DID again. Queued messages are unaffected (they are encrypted to wallets, not to the mediator).

## 6. Almena extensions

What is Almena's own. Each item either adds something DIDComm does not define or fixes a behaviour DIDComm leaves to the implementation.

### 6.1 Authenticated mediation

A profile of [CoordMed] and [Pickup]:

- Every Coordinate Mediation, Message Pickup and push-protocol message MUST be **authcrypted**. Anything else gets `e.m.trust.unauthenticated`.
- A mediation is keyed by the authenticated `from` (the *mediation DID*). Nobody can read or acknowledge another wallet's queue by claiming its DID.
- `mediate-request` is always granted and idempotent; `mediate-deny` is never sent. `mediate-grant` carries `routing_did: [<mediator DID>]`; the wallet puts that DID as the `uri` of its own `DIDCommMessaging` service.
- A recipient DID belongs to the **first** mediation that registers it; later `add`s from other mediations get `client_error`. DID URLs, non-DIDs, unknown actions and going over the per-mediation limit also get `client_error`. Removing a DID keeps its queued messages until picked up or expired.
- `recipient-query` returns all DIDs sorted; with `paginate`, a page plus `pagination {count, offset, remaining}`.
- One queue per **mediation**, not per recipient DID, so queue ids are unique across a wallet's DIDs; `recipient_did` filters within it and MUST be one of the mediation's (`e.m.msg.unknown-recipient`).
- `delivery` carries at most `min(limit, 100)` messages, oldest first, as `base64` attachments whose `id` is the queue id to acknowledge. Messages stay queued until `messages-received`.
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

Tokens reported invalid are deleted (FCM `UNREGISTERED`, `INVALID_ARGUMENT`; APNs `410`, `BadDeviceToken`, `DeviceTokenNotForTopic`). Other failures are logged, not retried.

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

1. If the sender is mediated here, the reply is queued for it (live push or wake-up as usual).
2. Otherwise it is wrapped for the sender's mediators and sent to its `DIDCommMessaging` service in the background, with the relay retries of §6.7.
3. A sender with no service, or whose service names this mediator without being registered here, gets nothing.

Replies to the mediator's own administrative messages are never wrapped for the wallet's mediators.

### 6.7 Federation without a registry

When a `forward`'s `next` is not registered here, the mediator routes the payload as a sender would: resolves `next`, wraps it for the hops of its `DIDCommMessaging` service, and POSTs it to the service URI. `ALMENA_FEDERATION=false` disables this (`404`).

- The first attempt happens before the mediator answers the `forward`; the answer is `202` once routing succeeded, whatever the attempt's outcome.
- Failed attempts are retried after 5 s, 30 s, 2 min and 10 min, then dropped. Retries survive restarts and are leased (60 s) so that several instances never send the same one. At most 1000 relays wait; beyond that a failed relay is dropped.
- A route that leads back to this mediator without a registration is `404`, not a loop.

### 6.8 Outbound request guard

Every outbound URL comes from a DID document, i.e. from strangers. Outbound HTTP (federation, `did:web`) MUST use `https`, MUST NOT target IP-literal hosts, and MUST NOT connect to private, loopback, link-local, CGNAT or documentation addresses — checked at connect time, so DNS rebinding cannot bypass it. `ALMENA_OUTBOUND_ALLOW_INSECURE=true` lifts the guard for local multi-mediator setups only.

### 6.9 TURN credentials

Wallets place calls with [WebRTC][webrtc] and relay all their media through TURN ([TURN]), so that neither side learns the other's IP address. Each wallet uses the TURN server of its own mediator, whose operator already sees its traffic. This protocol, Almena's own, hands a mediated wallet short-lived credentials for it:

| Protocol | PIURI | Messages |
|---|---|---|
| TURN 1.0 | `https://almena.id/protocols/turn/1.0` | `credentials-request`, `credentials` |

The PIURI is a fixed name, the same for every deployment; only the TURN server's address varies (`ALMENA_TURN_URLS`).

- `credentials-request`, body `{}`: authcrypted and with a granted mediation, like §6.1.
- Answered with `credentials`:

```json
{
  "ice_servers": [{
    "urls": ["turn:turn.example.com:3478?transport=udp", "turn:turn.example.com:3478?transport=tcp"],
    "username": "1760000000:9f3a61c2d4e5b708",
    "credential": "base64(HMAC-SHA1(secret, username))"
  }],
  "ttl": 86400
}
```

- Credentials follow [TURN-REST]: `username` is `<expiry, epoch seconds>:<id>`, `credential` is the base64 HMAC-SHA1 of `username` under the secret the mediator shares with the TURN server. Nothing is stored: the TURN server checks them on its own. The `id` is random per request, so the TURN server's records cannot be joined to a DID.
- Each entry of `ice_servers` has the members of WebRTC's `RTCIceServer` and can be handed to it as it is. `ttl` is in seconds.
- Offered only when the mediator is configured with a TURN server; otherwise `e.m.msg.unsupported-type`, and Discover Features does not disclose it (role `server` when it does).
- A wallet asks before each call; credentials must outlast the call, since the TURN server checks them again on every refresh.

The TURN server MUST NOT relay to private, loopback, link-local or CGNAT addresses other than its own relay address: wallets relay only to each other's relays, and anything else would open the operator's network to strangers.

### 6.10 Problem codes

Problem reports follow [DIDComm] §Problem Reports: they open a child thread of the trigger (`pthid` = the trigger's `thid`) and carry `ack: [<trigger id>]`. Codes used:

| Code | Origin | When |
|---|---|---|
| `e.m.msg.unsupported-type` | Almena | Type the mediator does not handle (`args`: the type). |
| `e.m.msg.invalid-body` | Almena | Body without the shape its type requires. |
| `e.m.req.time.expired` | Almena | `expires_time` has passed. |
| `e.m.trust.unauthenticated` | Almena | Mediation, pickup, push or TURN message not authcrypted. |
| `e.m.req.no-mediation` | Almena | Pickup, push or TURN message without a granted mediation. |
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
| `429` | Over the per-IP rate limit; with `Retry-After`. |
| `503` | Storage unavailable. |
| `507` | The recipient's queue is full (messages or bytes). |

### 7.2 WebSocket

`GET /ws` upgrades. One encrypted DIDComm message per frame (text or binary, up to `ALMENA_MAX_MESSAGE_BYTES`), both directions. `return_route` is implied on the socket. Frames count against the same per-IP rate limit as `POST /didcomm`; exceeding it closes the socket with code `1008`.

Live mode: the wallet sends an authcrypted `live-delivery-change` with `live_delivery: true` and is answered with `status` (`live_delivery: true`). From then on, each message queued for the mediation is pushed as a `delivery` with one attachment whose `id` is the queue id. Messages queued earlier are fetched with `delivery-request`. Live mode ends with the connection. A mediation is *online* while it has a live session; online mediations get no push.

### 7.3 Other endpoints

| Endpoint | Content |
|---|---|
| `GET /.well-known/did.json` | The mediator's DID document (§5.2). |
| `GET /oob/invitation` | The invitation (§6.5) and its URL form, as JSON. |
| `GET /oob` | Human-readable invitation page. |
| `GET /health` | Status, version and DID; `503` while storage is down. |
| `GET /` | Home page: status, DID, invitation QR and `almena://` link. |
| `GET /openapi.json`, `GET /docs` | API reference. |

TLS is terminated by a reverse proxy; the mediator speaks plain HTTP.

## 8. Discover Features disclosure

`disclose` answers with the features matching the queries (`*` is a wildcard; unknown feature types match nothing):

- `protocol`: every PIURI of §9 the mediator offers, with roles where they apply (`receiver`, `responder`, `mediator`, `notification-sender`, `server`);
- `header`: `return_route`;
- `constraint`: `max_receive_bytes` = `ALMENA_MAX_MESSAGE_BYTES`.

## 9. Protocols

| Protocol | PIURI | Defined in | Almena changes |
|---|---|---|---|
| Trust Ping 2.0 | `https://didcomm.org/trust-ping/2.0` | [DIDComm] | None; `ping-response` unless `response_requested: false`. |
| Discover Features 2.0 | `https://didcomm.org/discover-features/2.0` | [DIDComm] | §8, D9. |
| Report Problem 2.0 | `https://didcomm.org/report-problem/2.0` | [DIDComm] | §6.10. |
| `return_route` | header | [ReturnRoute] | D5, D6. |
| Coordinate Mediation 3.0 | `https://didcomm.org/coordinate-mediation/3.0` | [CoordMed] | §6.1, §6.2. |
| Routing 2.0 | `https://didcomm.org/routing/2.0` | [Routing] | D8, §6.7. |
| Message Pickup 3.0 | `https://didcomm.org/messagepickup/3.0` | [Pickup] | §6.1, D7, §7.2. |
| Out-of-Band 2.0 | `https://didcomm.org/out-of-band/2.0` | [DIDComm] | §6.5. |
| Push Notifications FCM 1.0 | `https://didcomm.org/push-notifications-fcm/1.0` | [FCM] | §6.3. |
| Push Notifications APNs 1.0 | `https://didcomm.org/push-notifications-apns/1.0` | [APNs] | §6.3. |
| ACK (notification) 1.0 | `https://didcomm.org/notification/1.0` | [Ack] | Emitted only, as the answer to `set-device-info`. |
| TURN 1.0 | `https://almena.id/protocols/turn/1.0` | This document | §6.9. |

## 10. Conformance evidence

- All nine vectors of [DIDComm] Appendix C (3 signed, 6 encrypted) pass at the JWS/JWE level and through full unpack (errata: D4). The spec's `did:key`, `did:peer:2` and `did:peer:4` examples are unit tests.
- Interoperability, both directions (`crates/interop`):
  - **didcomm-rust** 0.4: anoncrypt (A256CBC-HS512, A256GCM, XC20P) and authcrypt on X25519 and P-256, sender protection, Ed25519/P-256/secp256k1 signatures, plaintext, `forward` through the mediator.
  - **affinidi-messaging-didcomm** 0.15: anoncrypt and authcrypt on X25519, P-256, P-384, P-521, the three signature algorithms, and a full mediation run (ping, mediation, `forward`, pickup, acknowledgement) on X25519 and P-384.
  - **Veramo** 7.0.1 does **not** interoperate: its JWEs lack `apv` (and `apu` in authcrypt), and its authcrypt uses ECDH-1PU v3 defaulting to A256GCM, all outside DIDComm v2.0. The mediator answers `400`.
- Note: `anonymous_sender` in Almena's unpack metadata means "no authcrypt layer"; didcomm-rust also sets it when the sender is protected.

## 11. Limits

Limits are operator settings, not protocol: any wallet may request mediation, and access can later be narrowed (invitation-only, allowlist) without changing the protocol. Defaults:

| Setting | Default | Effect |
|---|---|---|
| `ALMENA_MAX_MESSAGE_BYTES` | 1 MiB | `413`; disclosed as `max_receive_bytes`. |
| `ALMENA_QUEUE_TTL` | 30 days | Undelivered messages dropped. |
| `ALMENA_QUEUE_MAX_MESSAGES` | 10 000 per mediation | `507`. |
| `ALMENA_QUEUE_MAX_BYTES` | 100 MiB per mediation | `507`. |
| `ALMENA_MAX_RECIPIENT_DIDS` | 100 per mediation | `client_error`. |
| `ALMENA_MEDIATION_TTL` | 90 days | A mediation with no authenticated mediation, pickup or push message for this long is removed, with its DIDs, queue and devices. |
| `ALMENA_RATE_LIMIT` | 60 / min / client IP | `429`, or WebSocket close `1008`. |
| `ALMENA_PUSH_MIN_INTERVAL` | 60 s | §6.4. |
| `ALMENA_TURN_TTL` | 1 day | Lifetime of TURN credentials (§6.9). |

The full list is in [.env.example](.env.example).

## 12. Security and privacy considerations

- **Content.** The mediator stores and forwards opaque envelopes encrypted to wallets. It learns recipient DIDs, sizes and timing, not content or senders of forwarded messages.
- **Queue ownership.** Authcrypt on every administrative message (§6.1) and possession proofs (§6.2) bind queues to wallets that control the DIDs.
- **Push.** Payloads carry nothing linkable to a DID, a sender or a message (§6.4). Push providers learn only that a device is being woken.
- **Calls.** Media is DTLS-SRTP between the two wallets; the TURN server relays it without being able to read it. It sees both wallets' IP addresses and the timing and volume of their calls, as the mediator already sees their messages' — which is why each wallet uses its own mediator's TURN server. TURN is offered over UDP and TCP without TLS: a network observer can see that a wallet uses TURN, but not what it carries.
- **Metrics.** Aggregate only — no DIDs, nothing per mediation — and served on a separate listener.
- **Outbound requests.** Guarded against SSRF (§6.8); `links` attachments refused (D8).
- **Keys.** The mediator's private keys are its identity; rotation is immediate (§5.3).

## 13. Not specified / not implemented

- DIDComm v1 envelopes; DIDComm v2.1 features beyond what §3.3 accepts on read.
- `forward` rewrapping, `delay_milli`, `links` attachments.
- A push gateway for third-party mediators (§6.4).
- TURN over TLS (`turns:`), and wake-ups for incoming calls (a call only rings on a wallet that is online).
- Live delivery across several mediator instances (sessions are per process).
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
| **Open with limits** | Any wallet may mediate; access can be narrowed later without protocol changes. | §11 |
| **`links` attachments refused** | SSRF and downloading on strangers' behalf; no tested client uses them. | D8 |
| **Live messages stay queued** until acknowledged | Mobile connections drop mid-delivery. | D7 |
| **Visible, content-free pushes** | Locked wallets cannot pick up in the background; iOS throttles silent pushes. (2026-09-24) | §6.4 |
| **Direct push mode** | Every mediator is run by the wallet's publisher for now. | §6.4 |
| **Stable invitation** | A printed QR code keeps working. | §6.5 |
| **No mediator registry** | `did:web` makes mediators discoverable by domain. | §6.7 |
| **Relay retries survive restarts** | A crash must not lose a relay. | §6.7, App. D |
| **Immediate key rotation**, no overlap | Rotation is mainly for a compromised key, which must stop working at once. | §5.3 |
| **Redis** with AOF | Queues survive restarts. | App. D |
| **One queue per mediation** | Queue ids unique across a wallet's DIDs. | §6.1 |
| **One instance** for now | Live sessions are in process. | App. E |
| **Metrics on their own listener**, aggregate only | Never exposed through the public proxy; no DIDs. | App. H |
| **TURN credentials from the mediator**, relay always | Calls never expose a wallet's IP to its contact; the operator who relays is the one the wallet already trusts; no second account. (2026-09-25) | §6.9 |
| **Fixed Almena PIURIs** (`https://almena.id/protocols/…`) | No DIDComm protocol exists for this; a PIURI is a name compared as text, so it cannot vary per environment. (2026-09-25) | §6.9 |

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

`almena-didcomm` knows nothing about HTTP, storage or mediation, so the wallet can depend on it (as a git dependency) when it needs to encrypt; if that becomes awkward it is extracted into its own project.

- Built on RustCrypto primitives (`x25519-dalek`, `ed25519-dalek`, `p256`, `p384`, `p521`, `k256`, `aes-kw`, `aes-gcm`, `chacha20poly1305`, `aes` + `cbc` + `hmac` + `sha2`). The Concat KDF is a few lines of our own (the `concat-kdf` crate lags behind `sha2`).
- DID resolution is a trait, so the mediator can add caching and the wallet can plug in its own. `LocalResolver` handles `did:key` and `did:peer`; `StaticResolver` holds fixed documents; `ChainResolver` combines them. `LocalResolver` keeps the `did:peer:4` long-form mapping in memory (bounded); the wallet will need to persist it.
- `pack_encrypted` wraps the message in `forward`s for the recipient's hops (`PackOptions::forward`, on by default) and returns the URI to POST to (`PackedMessage::service_uri`). `almena_didcomm::route` does the same for a payload the mediator relays.
- `PossessionProof` makes and checks the proofs of §6.2.

## Appendix C. Mediator keys

The three keys of §5.2 are generated on first start and kept in `ALMENA_KEYS_PATH` (default `data/keys.json`; `/data/keys.json` in the container, on the `mediator-data` volume) as JSON with the three private JWKs, mode `0600`. Mounting a file there brings your own keys. `almena-mediator rotate-keys` (`task rotate-keys` under Docker, which also restarts the container) writes new ones; they take effect on the next start. Other mediators cache the DID document for 5 minutes. The mediator resolves its own DID from memory.

## Appendix D. Storage

Redis, a service in `compose.yml`, with AOF persistence (`appendonly yes`, `appendfsync everysec`). The mediator refuses to start without its store (`ALMENA_REDIS_URL`, default `redis://localhost:6379`), and `/health` answers `503` while it is unreachable.

- Authentication is optional: `ALMENA_REDIS_PASSWORD` (it replaces any password in the URL; Compose passes it to Redis as `requirepass`). It never appears in logs or errors.
- Storage sits behind a `Store` trait (`crates/mediator/src/store/`) with a Redis and an in-memory implementation (`ALMENA_REDIS_URL=memory://`, development only). A shared contract test runs against both; the Redis run needs `ALMENA_TEST_REDIS_URL` (`task test:redis`).

| Key (`M` mediation DID, `R` recipient DID) | Type | Holds |
|---|---|---|
| `mediation:{M}` | string | Grant time |
| `mediation:{M}:recipients` | set | Recipient DIDs registered by `M` |
| `mediations:seen` | sorted set | Mediations by last wallet activity, for `ALMENA_MEDIATION_TTL` |
| `recipient:{R}` | string | The mediation that registered `R` |
| `mediation:{M}:queue` | stream | One entry per queued message: recipient and size |
| `mediation:{M}:msg:{id}` | string with TTL | The message itself |
| `mediation:{M}:bytes` | counter with TTL | Bytes queued, kept in step by the enqueue, expiry and removal scripts |
| `rate:{key}:{window}` | counter with TTL | Rate-limit hits (fixed window) |
| `push:{M}` | hash | Devices: service (`fcm`, `apns`) → `{token, platform}` as JSON |
| `push-sent:{M}` | string with TTL | Time of the last push, until the wallet picks up |
| `relay:due` | sorted set | Relays waiting for a retry, by when they are due (or leased until) |
| `relay:items` | hash | Relay id → `{uri, message, retries}` as JSON |

Bodies live outside the stream so `status` reads only small entries. Registration and enqueueing are Lua scripts, so they are atomic. Expired entries are trimmed on every read and write (`XTRIM MINID`); bodies expire on their own. Expired mediations are swept hourly. A background worker takes due relays every second and leases them for 60 s.

## Appendix E. Scaling

Live sessions are tracked in process (`dispatch/live.rs`), so the mediator runs as **one instance**. Behind a load balancer with several, a message queued by one instance would not be pushed live to a session on another (it would still be picked up), and that instance would send a needless push. When scaling out is needed: one Redis pub/sub channel every instance listens to and filters, plus a shared presence key with a TTL for the push check. Relay retries are already safe across instances (leases).

## Appendix F. Push gateway (planned)

Sending a push needs the credentials of the app that owns the token, which belong to the wallet's publisher. Today every mediator is run by the publisher (`ALMENA_PUSH_MODE=direct`). When third parties run mediators, they will instead send `{service, token}` to a gateway run by the publisher; nothing it sees is linked to a DID or to message content. Desktop wallets have no push: they receive over WebSocket while running and poll on start.

## Appendix G. Deployment and configuration

TLS is terminated by a reverse proxy. The first public mediator is `https://mediator.almena.id` (`did:web:mediator.almena.id`); its deployment waits until the wallet needs it. Development uses the same name, pointed at the developer's machine in `/etc/hosts` (Caddy with a Let's Encrypt certificate over DNS-01 in the domain's Cloudflare zone, `compose.yml`). The domain is not fixed anywhere: `ALMENA_DOMAIN` names it for Compose, the Caddyfile and Task, and `.env.example` derives `ALMENA_PUBLIC_URL`, `ALMENA_TURN_URLS` and `ALMENA_TURN_REALM` from it.

Settings beyond §11, all `ALMENA_*` environment variables (full list in [.env.example](.env.example)):

| Variable | Default | Meaning |
|---|---|---|
| `ALMENA_PUBLIC_URL` | `http://localhost:8080` | Public origin; gives the DID and endpoints (§5.1). |
| `ALMENA_KEYS_PATH` | `data/keys.json` | Mediator keys (App. C). |
| `ALMENA_REDIS_URL`, `ALMENA_REDIS_PASSWORD` | `redis://localhost:6379`, — | Storage (App. D). |
| `ALMENA_RECIPIENT_PROOF` | `required` | §6.2. |
| `ALMENA_FEDERATION` | `true` | §6.7. |
| `ALMENA_OUTBOUND_ALLOW_INSECURE` | `false` | §6.8. |
| `ALMENA_CLIENT_IP_HEADER` | — | Behind a proxy: header with the client IP; its **last** value is used. Unset: the TCP peer. |
| `ALMENA_PUSH_MODE` | `off` | `off` or `direct`. |
| `ALMENA_FCM_SERVICE_ACCOUNT` | — | Service account key (JSON) of the wallet app's Firebase project. |
| `ALMENA_APNS_KEY_PATH`, `ALMENA_APNS_KEY_ID`, `ALMENA_APNS_TEAM_ID`, `ALMENA_APNS_TOPIC` | — | APNs `.p8` key, its id, the team id and the app's bundle id; all four or none. |
| `ALMENA_APNS_SANDBOX` | `false` | Push to the APNs sandbox. |
| `ALMENA_METRICS_ADDR` | — | Metrics listener (App. H); off when unset. |
| `ALMENA_TURN_URLS`, `ALMENA_TURN_SECRET` | — | TURN URIs given to wallets (comma-separated `turn:`/`turns:`) and the secret shared with the TURN server; both or neither (§6.9). |
| `ALMENA_TURN_TTL` | `86400` | §6.9. |

The TURN server is coturn, a service of `compose.yml` under the `turn` profile (`COMPOSE_PROFILES=turn`), with `use-auth-secret` and the same secret. Its own settings: `ALMENA_TURN_EXTERNAL_IP` (the address relayed candidates carry: the host's public IP, or its LAN or loopback address in development), `ALMENA_TURN_PORT` (3478, UDP and TCP), `ALMENA_TURN_MIN_PORT`–`ALMENA_TURN_MAX_PORT` (the UDP relay ports, one per call leg) and `ALMENA_TURN_REALM`. It runs alone on its own Compose network at a fixed address (`172.31.254.2`), and refuses to relay into private networks except to that address and its external one (§6.9): two wallets on the same TURN server reach each other through its relay address, and nothing else on the host is reachable through it. Only UDP relays are allocated (`no-tcp-relay`).

## Appendix H. Metrics

Prometheus text format on `ALMENA_METRICS_ADDR`, hand-written counters. Aggregate only:

| Metric | Labels |
|---|---|
| `almena_mediator_info` | `version` |
| `almena_didcomm_messages_total` | `transport` (`http`, `websocket`), `outcome` (`accepted`, `reply`, `rejected`) |
| `almena_rate_limited_total` | — |
| `almena_forwards_total` | `result` (`queued`, `relayed`, `relay_scheduled`, `relay_dropped`, `refused`) |
| `almena_relay_retries_total` | `result` (`delivered`, `rescheduled`, `abandoned`) |
| `almena_pushes_total` | `service` (`fcm`, `apns`), `result` (`delivered`, `invalid_token`, `failed`) |
| `almena_live_sessions` (gauge) | — |
| `almena_mediations_granted_total`, `almena_mediations_removed_total` | — |
| `almena_turn_credentials_total` | — |

## Appendix I. Phases

1. ✅ **`almena-didcomm`** — message model, keys, `did:key` / `did:peer`, JWS, anoncrypt and authcrypt, pack/unpack with consistency checks and `from_prior`, spec test vectors.
2. ✅ **Mediator skeleton** — identity and keys, `did:web` document, `POST /didcomm`, Redis, Trust Ping, Discover Features, Report Problem, `return_route`.
3. ✅ **Mediation** — Coordinate Mediation 3.0, `forward`, Message Pickup 3.0 (polling), limits.
4. ✅ **Live and network** — WebSocket and live delivery, Out-of-Band invitations, federation.
5. ✅ **Push** — FCM and APNs protocols, token storage, coalesced wake-ups, direct mode. The push gateway (App. F) waits for third-party mediators.
6. ✅ **Calls** — TURN credentials (§6.9) and coturn in `compose.yml`. Wake-ups for incoming calls come later.

Each phase ends with `task check` green and this document updated.

[didcomm]: https://identity.foundation/didcomm-messaging/spec/v2.0/
[did]: https://www.w3.org/TR/did-core/
[didkey]: https://w3c-ccg.github.io/did-method-key/
[didpeer]: https://identity.foundation/peer-did-method-spec/
[didweb]: https://w3c-ccg.github.io/did-method-web/
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
[rfc8656]: https://www.rfc-editor.org/rfc/rfc8656
[turnrest]: https://datatracker.ietf.org/doc/html/draft-uberti-behave-turn-rest-00
[webrtc]: https://www.w3.org/TR/webrtc/
[coturn]: https://github.com/coturn/coturn
