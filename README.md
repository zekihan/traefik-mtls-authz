# Traefik mTLS Authorization

A Traefik middleware plugin for per-application client certificate authorization.

Traefik verifies the certificate with `RequireAndVerifyClientCert`. This plugin
requires that verified TLS state, pins its trust anchor, checks the entire chain's
current validity, and authorizes one exact enrolled URI SAN per application.
There are no runtime dependencies outside the Go standard library.

## Status

The v0.1.1 implementation replaces the v0.1.0 deny-all skeleton. It includes strict
configuration validation, fingerprint blocking, disabled identities, exact
method/path constraints, identity-header stripping and optional forwarding.
The Docker Compose suite verifies real Traefik v3.7.14 / Yaegi loading, HTTP/1.1
and HTTP/2 on both TLS versions, session resumption, PROXY v2, routing failures,
and stream behavior.
These are local fixture tests; deployment and GitOps integration belong in the
argocd repository. No production routes have been changed by this implementation.

## Configuration

Use a separate policy for each application. Identities are case-sensitive URIs
such as `urn:noqer:mtls:clients:z-mac`. CNs and inbound headers never provide identity.
Leaf certificates must contain exactly one SAN entry: the identity URI. Every
additional SAN is rejected, including types Go ignores. Identity comparison uses
the raw URI SAN bytes; an uppercase `URN:` scheme is
rejected even though Go's URL parser normalizes it. `identityPrefix` must name a
full profile such as `urn:noqer:mtls:clients:`; broader prefixes are rejected.
The issuer fingerprint is the SHA-256 of the verified chain's root certificate
DER, not of its PEM file or its intermediate.

Use `policyJSON` with every Traefik provider, including Kubernetes, to preserve strict types. In
particular, Traefik's **file provider stringifies scalar map values** before the
plugin decoder runs; a structured `policy` object therefore fails validation
there. The native `policy` object remains available for direct callers, but its
successful loading through the Kubernetes CRD provider is unverified. See
[the design](docs/design.md#5-configuration). `policy` and `policyJSON` are mutually
exclusive; unknown keys and wrong types fail loading.

File-provider example (replace the illustrative fingerprint with your CA's):

```yaml
http:
  middlewares:
    app-authz:
      plugin:
        traefik-mtls-authz:
          policyJSON: |
            {
              "schemaVersion": 1,
              "app": "sonarr",
              "policyRevision": "1-3f9c2a1b",
              "trustedIssuers": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
              "identityPrefix": "urn:noqer:mtls:clients:",
              "identities": ["urn:noqer:mtls:clients:z-mac"],
              "disabledIdentities": [],
              "blockedFingerprints": [],
              "constraints": {},
              "stripHeaders": true,
              "forwardIdentityHeader": ""
            }
```

Header stripping is mandatory. Successful requests lose `X-Forwarded-Tls-Client-Cert`,
`X-Forwarded-Tls-Client-Cert-Info` and all `X-Mtls-*` headers. To pass the verified
identity to a backend, configure `forwardIdentityHeader: "X-Mtls-Identity"` inside
the policy. It is off by default. The header must be in the dedicated `X-Mtls-*`
namespace with a non-empty suffix; its value replaces any inbound value. Denials return HTTP 403,
`forbidden`, `Cache-Control: no-store` and `X-Mtls-Authz-Reason`.
Stripping applies to the initial HTTP headers. The plugin does not inspect or filter
trailers, which are populated as the body is consumed; backends must use the
verified initial identity header rather than trailer fields.

Constraint keys must be enrolled in that application's `identities` list; typos
and unused rules fail policy loading. Constraints compare the HTTP method and
middleware-visible path exactly. Paths
must be absolute literal paths without a trailing slash (except `/`), `//`, `..`,
query, fragment, backslash or characters needing percent-encoding. Encoded
separators are rejected even when the entrypoint allows them. Traefik normalizes
unreserved encodings before the middleware and forwards the same canonical path;
for example `%75pload` becomes `upload` for both authorization and the backend. The optional fingerprint `expires` date is
informational: a blocked fingerprint stays blocked until removed from the policy.

## Deployment contract

Read [the full deployment contract](docs/design.md#7-deployment-contract-what-the-plugin-assumes-enforced-outside-this-repo)
before attaching a middleware to a route. It requires:

- `RequireAndVerifyClientCert`, `sniStrict: true`, disabled session tickets and the intended CA bundle.
- `core.strictTLSOptions: true` and `experimental.abortOnPluginFailure: true`.
- A pinned plugin version and catalog archive hash.
- Authorization first on **every** router that can serve an mTLS host, including alternate and catch-all routes.
- Consistent global policy fields and visible policy revisions across applications.

A failed middleware constructor removes its router. Another matching router may
still serve the request; the plugin cannot enforce coverage of other routers.
Policy reloads take effect on the next HTTP request. Existing WebSockets and
uploads continue and require separate connection draining when access is withdrawn.

## Development

```sh
make tidy
make lint
make test
make check/docs
make test/integration
```

The integration suite requires Linux, Docker Engine and Docker Compose v2. It uses
an image pinned by digest, loopback entrypoints, ephemeral ports and generated PKI.
Private keys are temporary, never committed or copied into logs. See
[testing/README.md](testing/README.md) for the acceptance matrix and artifacts.

## Releases

`VERSION` contains the next release version without `v`; tags use `v0.1.1`.
The release workflow requires unit, documentation and real-Traefik checks before
publishing a source release. The public repository needs the `traefik-plugin`
topic for catalog discovery. After catalog indexing, download the exact catalog
archive and append its SHA-256 to the release notes with
`scripts/catalog_hash.sh v0.1.1`. Operators pin that hash with the version.
Never substitute the hash of GitHub's source zip for the catalog archive hash.

## License

MIT. See [LICENSE](LICENSE).
