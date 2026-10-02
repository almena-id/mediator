# almena-mediator — notes for contributors and agents

Server of Almena Network, a decentralised messaging platform based on DIDComm Messaging v2.0
(https://identity.foundation/didcomm-messaging/spec/v2.0/). DIDs follow W3C DID (https://www.w3.org/TR/did/). Phases 1–6 of SPEC.md (Appendix I) are done: the DIDComm library, the mediator skeleton, mediation, live delivery / invitations / federation, push wake-ups, and TURN credentials for calls.

This project is independent: it has its own Docker Compose file, env file and tooling.
It shares nothing with `../wallet` except the protocol; the wallet may later depend on the `almena-didcomm` crate (see SPEC.md, Appendix B).

## Layout

Cargo workspace:

- `crates/didcomm/` — `almena-didcomm`: DIDComm v2.0 library (keys, JWS, JWE anoncrypt/authcrypt, messages, pack/unpack, `did:key`/`did:peer` resolution, possession proofs). No HTTP or storage.
  - `tests/spec/appendix.json` — the spec's Appendix A–C test vectors (errata noted in the file).
- `crates/interop/` — `almena-interop`, tests only: `almena-didcomm` and the mediator against didcomm-rust (SICPA) and Affinidi's DIDComm library, both ways. Nothing else depends on it.
- `interop/veramo/` — a Veramo client run against a live mediator (`node check.ts`); Veramo does not conform yet, see SPEC.md §10.
- `crates/mediator/` — `almena-mediator`: the service.
  - `config` reads `ALMENA_*` env vars; `identity` holds the mediator's `did:web`, keys (`ALMENA_KEYS_PATH`) and DID document.
  - `store/`: the `Store` trait with Redis and in-memory implementations, and a contract test both must pass.
  - `dispatch/`: unpacks what reaches `/didcomm` or `/ws` and dispatches — `protocols.rs` (Trust Ping, Discover Features, problem reports), `mediation.rs` (Coordinate Mediation, `forward`), `pickup.rs` (Message Pickup), `live.rs` (live-delivery sessions), `relay.rs` (forwarding to other mediators), `devices.rs` (push protocols: device registration), `turn.rs` (TURN 1.0, Almena's own: time-limited credentials for the coturn relay, nothing stored).
  - `push/`: wake-ups through FCM (`fcm.rs`) and APNs (`apns.rs`), coalescing, the `Pusher` trait.
  - `transport.rs`: outbound HTTPS with the SSRF guard, and the `did:web` resolver. `oob.rs`: the Out-of-Band invitation.
  - `routes` is the axum router: HTTP and WebSocket endpoints, rate limit, HTTP status mapping.
  - `home.rs`: the page at `/` (the status, version and DID `/health` also gives, the invitation QR and its `almena://` link); the icon (`crates/mediator/assets/icon.png`, compiled in) is the favicon. Its `layout` wraps every browser page (also `/oob`) in the header and footer of Almena's portals (catalog, registry, status) and their typefaces: Chakra Petch (brand, headings), Inter (text), JetBrains Mono (values), compiled in from `crates/mediator/assets/fonts` (SIL OFL, licences beside them) and served at `/fonts/{name}`, so a page never calls a third party.
  - `metrics.rs`: Prometheus counters, served by their own listener (`ALMENA_METRICS_ADDR`), not by the router.
  - `src/main.rs`: logging, start-up, graceful shutdown, `healthcheck` subcommand. `testing.rs` has a test mediator and wallets.
  - `examples/smoke.rs`: end-to-end client against a running mediator (`task smoke`).
- `Dockerfile`, `compose.yml` (mediator + Redis + Caddy, and coturn under the `turn` profile), `.env.example` — container build and local run. `data/` (local keys) and `caddy/` (Caddy's certificates and ACME account) are git-ignored.
- `SPEC.md` — the Almena Mediator specification: the DIDComm v2.0 profile, deviations and Almena's own extensions, with their sources; its appendices hold the design (decisions, code layout, storage, scaling, metrics, phases). Read it before DIDComm work and keep it current.

## Rules

- Blue `#2f6fed` is the mediator's identity, the wallet's blue accent and the colour `assets/icon.png` is drawn in: `--brand` in `home.rs` (`LAYOUT_CSS`), carried by the mark in the header and footer and the "Open in Almena wallet" button. Green and red carry the status only. The identity colours across Almena: status cyan `#3fe0ff`, catalog blue `#2563eb`, registry green `#1f9d55`, mediator blue `#2f6fed`, landing orange `#eb7229`, docu yellow `#f2b705`, the wallet the person's choice (orange by default).

- Everything is written in English.
- `almena-didcomm` denies `unwrap`/`expect` outside tests (`clippy.toml` allows them in tests) and uses `thiserror`; the mediator binary uses `anyhow`.
- Every HTTP endpoint of the public router is declared with `#[utoipa::path]` and registered through `OpenApiRouter` in `crates/mediator/src/routes.rs`, so it appears in `/openapi.json` and `/docs`. Keep the README endpoint table in sync.
- Tasks live in `Taskfile.yml` (`task --list`). Before finishing a change: `task check` (fmt check, clippy -D warnings, tests).
