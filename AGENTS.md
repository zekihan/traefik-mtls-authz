# AGENTS.md

This repository is a Traefik middleware plugin for per-application mTLS authorization.
v0.1.0 is a deny-all skeleton, not a usable authorization implementation.

Run `make tidy`, `make lint`, and `make test` before committing.
Keep code compatible with Traefik's Yaegi interpreter: avoid generics and verify
real Traefik loading before claiming production compatibility.

The implementation design is in docs/design.md; follow it.

Security contracts for future implementation:
- Native Traefik RequireAndVerifyClientCert performs certificate validation.
- Require verified TLS state; never accept client identity from HTTP headers.
- Authorize exact enrolled URI SAN identities per application; default deny.
- Reject ambiguous identities and malformed policy; support fingerprint blocking.
- Never include private keys or credentials in this repository.
- Test plugin-load failure, TLS resumption, alternate routes, and WebSocket/stream
  behavior before deployment. Policy changes do not terminate existing streams.
