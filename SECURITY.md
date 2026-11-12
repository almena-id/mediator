# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: on
[almena-id/mediator](https://github.com/almena-id/mediator), open the
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue, pull request or discussion about it.

Include what you can of:

- the component (`almena-didcomm` or `almena-mediator`) and the version or commit;
- what an attacker can do, and under which configuration;
- steps or a proof of concept to reproduce it.

We aim to acknowledge a report within 3 working days and to agree on a
disclosure date with you once the issue is understood. We credit reporters in
the release notes unless you prefer otherwise.

## Supported versions

The project is before its first release: only the `main` branch receives
security fixes.

## Scope

In scope, among others:

- the DIDComm library: envelope parsing, decryption, signature checks,
  consistency between envelopes and headers, DID resolution;
- the mediator: access to another wallet's queue or registered DIDs, recipient
  proofs, message leaks, the SSRF guard on outbound requests (federation,
  `did:web`, the onboarding's domain check), rate limits and quotas, push
  tokens and credentials;
- the onboarding and the administration portal: claiming a mediator without
  its setup code, proving a domain one does not control, signing in as
  another administrator, sessions, invitations, a private mediator's access;
- anything that exposes the mediator's private keys (`keys.json`), secrets
  (FCM/APNs credentials, the setup code) or databases (`mediator.db`,
  `admin.db`).

Out of scope:

- the development setup (`task dev`, `ALMENA_PUBLIC_URL`,
  `ALMENA_OUTBOUND_ALLOW_INSECURE`) and the proxy in front of a mediator,
  which is its operator's;
- denial of service that needs more traffic than the configured rate limits
  let through;
- third-party DIDComm implementations used only by the interoperability
  tests (`crates/interop`, `interop/`).

The specification and design, including what the mediator deliberately does
not do, are in [SPEC.md](SPEC.md).
