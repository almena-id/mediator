# almena-mediator

The mediator of Almena Network: a [DIDComm Messaging v2.0](https://identity.foundation/didcomm-messaging/spec/v2.0/) mailbox for wallets. It queues end-to-end encrypted messages until their wallet picks them up (over HTTPS, or live over a WebSocket), relays messages for wallets mediated elsewhere, wakes mobile wallets with content-free push notifications, and gives its wallets credentials for a TURN relay (coturn) for their calls. It never sees message or call content.

It implements Coordinate Mediation 3.0, Routing 2.0, Message Pickup 3.0 (with live mode), Trust Ping, Discover Features, Report Problem and Out-of-Band 2.0, plus its own TURN 1.0 for call relay credentials, on top of `almena-didcomm` (`crates/didcomm`), its own DIDComm library. [SPEC.md](SPEC.md) specifies the Almena Mediator — its profile of DIDComm v2.0 and what it adds — and, in its appendices, the design and every decision behind it.

## Quick start

Needs Rust, [Task](https://taskfile.dev) and Docker.

```bash
task init   # .env from .env.example
task up     # mediator + Redis + Caddy (HTTPS) in Docker
```

It answers at `https://$ALMENA_DOMAIN` (`mediator.dev.almena.network` in `.env.example`; the Caddy site, public URL and TURN URIs all follow it) and at `http://localhost:8080`. Point the name at this machine (in `/etc/hosts` for development); the Let's Encrypt certificate needs the domain's zone in Cloudflare and `CLOUDFLARE_API_TOKEN` (Zone / DNS / Edit) in `.env`. Without Docker, `task dev:memory` runs it in-process with everything in memory.

```bash
task health   # {"status":"ok",…}
task smoke    # end-to-end check: mediation, a forwarded message, pickup
```

Every merge into `main` publishes the image `ghcr.io/almena-network/mediator` (amd64 and arm64) with a `year.month.sequence` version (e.g. `2026.09.1`, the sequence restarting each month), also tagged `latest` and `sha-<commit>`; the commit gets the git tag `v<version>`.

## Configuration

All settings are `ALMENA_*` environment variables; [.env.example](.env.example) lists and explains every one. The ones you are most likely to set:

| Variable | Default | |
|---|---|---|
| `ALMENA_DOMAIN` | — | Domain of the deployment, for Docker Compose, Caddy and Task; `.env.example` derives the public URL and TURN URIs from it |
| `ALMENA_PUBLIC_URL` | `http://localhost:8080` | Public origin; the mediator's DID is its `did:web` |
| `ALMENA_REDIS_URL` / `ALMENA_REDIS_PASSWORD` | `redis://localhost:6379` / — | Storage (`memory://` for development) |
| `ALMENA_PUSH_MODE` | `off` | `direct` to wake wallets through FCM/APNs |
| `ALMENA_TURN_URLS` / `ALMENA_TURN_SECRET` | — | TURN relay for calls: URIs given to wallets and the secret shared with coturn (`task init` generates it; coturn runs under the `turn` Compose profile) |
| `ALMENA_METRICS_ADDR` | — | Prometheus metrics on their own address |

Keep `keys.json` (the `mediator-data` volume) private and backed up: it is the mediator's identity.

## Endpoints

| | |
|---|---|
| `GET /`, `GET /icon.png` | Home page: icon, name, status, version, DID, the invitation QR and an `almena://` link to open it in the wallet |
| `POST /didcomm`, `GET /ws` | DIDComm over HTTPS and WebSocket |
| `GET /.well-known/did.json` | The mediator's DID document |
| `GET /oob/invitation`, `GET /oob` | Out-of-Band mediation invitation (JSON, and a page for its QR URL) |
| `GET /health` | Health, `503` while storage is down |
| `GET /docs`, `GET /openapi.json` | API reference, generated from the code |

## Development

`task --list` shows every task. Before sending a change, `task check` (formatting, clippy, tests) must pass; see [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for the code layout.

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
