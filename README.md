# almena-mediator

The mediator of Almena ID: a [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/) mailbox for wallets. It queues end-to-end encrypted messages until their wallet picks them up (over HTTPS, or live over a WebSocket), relays messages for wallets mediated elsewhere and wakes mobile wallets with content-free push notifications. It never sees message content.

It implements Coordinate Mediation 3.0, Routing 2.0, Message Pickup 3.0 (with live mode), Trust Ping, Discover Features, Report Problem and Out-of-Band 2.0, on top of `almena-didcomm` (`crates/didcomm`), its own DIDComm library. [SPEC.md](SPEC.md) specifies the Almena Mediator — its profile of DIDComm v2.0 and what it adds — and, in its appendices, the design and every decision behind it.

## Quick start

Needs Rust, [Task](https://taskfile.dev) and Docker.

```bash
task init   # .env from .env.example
task up     # the mediator in Docker
```

It answers plain HTTP at `http://localhost:8080` (loopback only). This project is the mediator and nothing in front of it: TLS and the public name are the business of whoever runs it, with the reverse proxy of their choice (locally, `../develop`'s Caddy). The proxy must reach the mediator, serve its public URL over HTTPS with a valid certificate, and — for the rate limit to count clients, not the proxy — set a client IP header the mediator is told about (`ALMENA_CLIENT_IP_HEADER`). Without Docker, `task dev:memory` runs it in-process with everything in memory.

### Setting it up

A new mediator starts unconfigured: it writes a one-time **setup code** to its log (`almena-mediator setup` prints a new one) and serves only `/setup`. There the operator gives the URL it will be published at, which becomes its `did:web`, and chooses **public** (any wallet keeps its mailbox here) or **private** (only the wallets its administrators invite). The URL is proven before it is taken: a TXT record at `_almena-mediator.<host>` and `https://<host>/.well-known/almena-setup` must both show the value the page gives. Then the mediator starts in full on the same port, and the page goes on by itself to `<url>/setup`, with the same code, which makes its first **administrator**: whoever signs in there with the Almena wallet (the QR code changes every minute until a wallet reads it). Until then `/` leads to `/setup`. Administrators sign in at `/portal` the same way, to a dashboard: an **overview** (mailboxes against the ceiling, messages waiting, recipient DIDs, push devices, relays pending, the site), the **mailboxes** (searched by any of their DIDs, with what waits in each; removing one deletes it all), on a private mediator its **members** and their invitations (a QR code and a link, good for as many wallets and days as chosen), the **administrators** (all equal: they invite each other with a one-use link for 7 days and remove each other) and the **site**. The mode never changes. The URL can move: the new domain is proven the same way, then the mediator restarts as the new `did:web` — every wallet connects again, and the administrators are invited again at the new address, since the wallet signs in with a key per address. `ALMENA_PUBLIC_URL` (and `ALMENA_ACCESS`) skip the onboarding for development and tests (`task dev` sets it), and pin the URL to the variable; they are not part of a deployment's `.env`.

```bash
task health   # {"status":"ok",…}
task smoke    # end-to-end check: mediation, a forwarded message, pickup
              # (a private mediator: task smoke -- <url> '<invitation link>')
```

There is no CI: images are built locally (`task up`, `task docker:build`). A build argument `ALMENA_VERSION` sets the version `/health` reports; without it, the crate's.

## Configuration

All settings are `ALMENA_*` environment variables; [.env.example](.env.example) lists and explains every one. The ones you are most likely to set:

| Variable | Default | |
|---|---|---|
| `ALMENA_PUBLIC_URL` / `ALMENA_ACCESS` | — / `public` | Development and tests only (`task dev` sets it): skip the onboarding with this public origin and mode. Never in `.env`: a deployed mediator is set up through `/setup` |
| `ALMENA_ADMIN_DB_PATH` | `data/admin.db` | The administration's SQLite database: the site, the administrators, the setup code |
| `ALMENA_DB_PATH` | `data/mediator.db` | The SQLite database: mediations, queues, devices, relays (`:memory:` for development) |
| `ALMENA_PUSH_MODE` | `off` | `direct` to wake wallets through FCM/APNs |
| `ALMENA_METRICS_ADDR` | — | Prometheus metrics on their own address |
| `ALMENA_CLIENT_IP_HEADER` / `ALMENA_TRUSTED_PROXIES` | — / loopback and private ranges | Behind a proxy: the header with the client IP, believed only from those peers (CIDRs) |
| `ALMENA_RATE_LIMIT` / `ALMENA_RELAY_RATE_LIMIT` | `60` / `600` | Messages per minute per client; relays per minute per destination host |
| `ALMENA_MAX_MEDIATIONS` / `ALMENA_MAX_SOCKETS` | `10000` / `5000` | Ceilings in all: mediations held, WebSockets open; past them only what is new is refused (SPEC.md §11) |

Keep `keys.json` (the `mediator-data` volume) private and backed up: it is the mediator's identity. Beside it, `mediator.db` holds the queues and `admin.db` the site and its administrators; the mediator runs as one instance.

## Endpoints

| | |
|---|---|
| `GET /`, `GET /icon.png` | Home page (and its favicon): status, version, DID, the invitation QR and an `almena://` link to open it in the wallet |
| `GET /fonts/{name}` | The typefaces of the mediator's pages (WOFF2), served by the mediator itself |
| `POST /didcomm`, `GET /ws` | DIDComm over HTTPS and WebSocket |
| `GET /.well-known/did.json` | The mediator's DID document |
| `GET /.well-known/security.txt` | Where to report a vulnerability ([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)): this repository's private advisories; `Expires` stays 180 days ahead |
| `GET /oob/invitation`, `GET /oob` | Out-of-Band mediation invitation (JSON, and a page for its QR URL, which opens the invitation it is given: a member's, on a private mediator) |
| `GET /health` | Health, `503` while storage is down; `capacity: full` while new mediations are denied; `status: setup` while not set up |
| `GET /setup`, `POST /setup`, `POST /setup/site`, `POST /setup/check`, `GET /.well-known/almena-setup` | The onboarding (the code always posted, never in a URL), served alone until the mediator is set up; once it is, `POST /setup` with the code makes the first administrator, and the well-known answers for a domain the URL is moving to |
| `GET /portal`, `POST /portal/sign-in/status`, `POST /portal/sign-in/renew`, `POST /portal/sign-out` | The administration portal: signing in with the Almena wallet, then the dashboard's overview |
| `GET /portal/mailboxes`, `POST /portal/mailboxes/remove` | Every mailbox, the most recently active first, searched by any of its DIDs; removing one |
| `GET /portal/members`, `GET /portal/admins` | A private mediator's members and their invitations; the administrators and theirs |
| `GET /portal/site`, `POST /portal/site/url`, `POST /portal/site/check`, `POST /portal/site/cancel` | The site; moving the URL to a proven domain, which restarts the mediator as the new `did:web` |
| `POST /portal/invitations`, `GET /portal/invitations/{id}`, `POST /portal/invitations/{id}/withdraw` | Member invitations (a private mediator's): made, shown as a QR code and links, withdrawn |
| `POST /portal/admins/invite`, `GET /portal/join/{id}`, `POST /portal/admins/remove`, `POST /portal/members/remove` | Inviting an administrator and joining by the link; removing administrators and members |
| `GET /portal/requests/{id}`, `POST /portal/requests/{id}/response` | The sign-in request the wallet reads, and its `id_token` answer (SIOPv2 `direct_post`, as the registry's) |
| `GET /docs`, `GET /openapi.json` | API reference, generated from the code |

## Development

`task --list` shows every task. Before sending a change, `task check` (formatting, clippy, tests) must pass; see [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the code layout.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
