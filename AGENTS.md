# AGENTS.md

This repository is a Traefik middleware plugin for per-application mTLS authorization.
The v0.1.1 implementation replaces the historical v0.1.0 deny-all skeleton.
Local acceptance tests do not imply a production deployment.

Run `make tidy`, `make lint`, and `make test` before committing. Run `make check/docs`
after editing fenced YAML in docs/ or README.md.
Keep code compatible with Traefik's Yaegi interpreter: avoid generics and verify
real Traefik loading before claiming production compatibility.

The implementation design is in docs/design.md; follow it.

Security contracts:
- Native Traefik RequireAndVerifyClientCert performs certificate validation.
- Require verified TLS state; never accept client identity from HTTP headers.
- Authorize exact enrolled URI SAN identities per application; default deny.
- Reject ambiguous identities and malformed policy; support fingerprint blocking.
- Never include private keys or credentials in this repository.
- Test plugin-load failure, TLS resumption, alternate routes, and WebSocket/stream
  behavior before deployment. Policy changes do not terminate existing streams.
