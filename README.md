# Traefik mTLS Authorization

A self-owned Traefik middleware plugin for per-application client certificate authorization.

## Status

**v0.1.0 is a repository skeleton. It returns HTTP 403 for every request.**
Do not attach this release to production routes. Certificate authorization and
real-Traefik/Yaegi integration tests are not implemented yet.

## Planned model

Traefik validates client certificates using a dedicated private client CA and
`RequireAndVerifyClientCert`. The plugin will require verified TLS state and
apply an explicit per-application allowlist of enrolled URI SAN identities.
One device/workload certificate can be authorized for multiple applications.
Browser apps and journald uploaders can share the client CA while retaining
separate endpoint permissions. HTTPS server certificates remain independent.

Planned safeguards include default deny, exact identity matching, certificate
fingerprint blocking, and rejection of unverified TLS and forged identity headers.
Existing WebSockets and upload streams require separate connection draining when
access is withdrawn. No CA consolidation or live ingress migration is part of
this skeleton release.

## Design

The implementation design, request authorization algorithm, configuration schema and
acceptance criteria are in [docs/design.md](docs/design.md).

## Development

```sh
make tidy
make lint
make test
```

The module exposes Traefik's `CreateConfig`, `New`, and `ServeHTTP` interfaces.
It uses only the Go standard library. `.traefik.yml` contains plugin metadata.
Policies and the supported configuration schema will be added with implementation.

## Releases

`VERSION` contains the version without the `v` prefix. Git tags use `v0.1.0`.
The release workflow validates code before publishing a GitHub source release.

## License

MIT. See [LICENSE](LICENSE).
