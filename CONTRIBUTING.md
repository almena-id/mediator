# Contributing

Thanks for helping with the Almena ID mediator. By taking part you agree
to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security issues go
through [SECURITY.md](SECURITY.md), never through public issues.

## Getting started

You need a recent stable Rust, [Task](https://taskfile.dev) and Docker (for
Redis and the full stack).

```bash
task init        # creates .env from .env.example
task dev:memory  # runs the mediator without Docker, everything in memory
task dev         # runs it against Redis in Docker
task up          # the full stack in Docker, behind Caddy
task --list      # everything else
```

[README.md](README.md) lists the configuration and endpoints;
[SPEC.md](SPEC.md) is the specification and the design. Read it before
changing anything DIDComm-related, and keep it current with your change.

## Making a change

- Open an issue first for anything larger than a small fix, so the approach
  can be agreed before the code.
- Everything is written in English: code, comments, docs, commit messages.
- `almena-didcomm` never panics outside tests (`unwrap`/`expect` are denied)
  and uses `thiserror`; the mediator uses `anyhow`.
- Every endpoint of the public router is declared with `#[utoipa::path]`, so it
  shows up in `/openapi.json` and `/docs`; keep the README endpoint table in
  sync.
- New behaviour comes with tests. Storage changes go into the shared contract
  test that both stores run; run it against Redis with `task test:redis`.
- Before sending a change, `task check` must pass: formatting, clippy with
  warnings as errors, and all tests.

[AGENTS.md](AGENTS.md) describes the layout of the code.

## Pull requests

Keep a pull request to one topic, describe what it changes and why, and link
the issue it addresses. By contributing you agree that your contribution is
licensed under the [Apache License 2.0](LICENSE), as the rest of the project.
