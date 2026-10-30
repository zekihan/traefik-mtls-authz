Per-application mTLS authorization replaces the v0.1.0 deny-all skeleton.

- Require verified TLS state, pin the trust anchor, and recheck every certificate's validity on every request.
- Authorize exactly one enrolled raw URI SAN per application; reject ambiguous and malformed SANs.
- Support certificate fingerprint blocking, disabled identities, and exact method/path constraints. Constraint keys must be enrolled.
- Strip inbound identity headers and optionally forward a verified X-Mtls-* identity header.
- Validate policies strictly. Use policyJSON for provider configuration to preserve types through Traefik's parser.
- Send bounded identity logs through Traefik's logger, respecting levels, metadata, JSON formatting, and file destinations.

Validation includes unit/race, vet, docs checks and pinned real Traefik v3.7.14 / Yaegi acceptance tests: HTTP/1.1 and HTTP/2 over TLS 1.2/1.3, resumption/ticket behavior, PROXY v2, policy reload, CA expiry on keep-alive, WebSockets, streaming, routing fallbacks, and plugin-load/compile failures.

Read README.md and docs/design.md before deployment. Authorization must cover every matching router; policy changes do not terminate existing streams. Kubernetes provider loading and live catalog delivery are separate from the local runtime acceptance tests. No production routes are changed by this release.

Catalog archive SHA-256: pending catalog indexing. The exact digest will be appended after the catalog serves v0.1.1; operators must pin both version and that archive hash.
