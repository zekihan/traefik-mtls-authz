# Traefik mTLS Authorization

A Traefik middleware plugin for per-application client certificate authorization.

[![Traefik Plugin](https://img.shields.io/badge/Traefik%20Plugin-Traefik%20mTLS%20Authorization-blue)](https://plugins.traefik.io/plugins/6ae44f4d45a3588988cfca95/traefik-m-tls-authorization)
[![Version](https://img.shields.io/badge/version-0.1.1-green)](https://github.com/zekihan/traefik-mtls-authz/releases/tag/v0.1.1)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/zekihan/traefik-mtls-authz/blob/main/LICENSE)
[![Checks](https://github.com/zekihan/traefik-mtls-authz/actions/workflows/pr.yaml/badge.svg)](https://github.com/zekihan/traefik-mtls-authz/actions/workflows/pr.yaml)

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

## Installation

### Plugin Catalog

Find the plugin in the
[Traefik Plugin Catalog](https://plugins.traefik.io/plugins/6ae44f4d45a3588988cfca95/traefik-m-tls-authorization).
The current release is [v0.1.1](https://github.com/zekihan/traefik-mtls-authz/releases/tag/v0.1.1).

### Static Configuration

Add the plugin to your Traefik static configuration and restart Traefik:

```yaml
core:
  strictTLSOptions: true

experimental:
  abortOnPluginFailure: true
  plugins:
    traefik-mtls-authz:
      moduleName: github.com/zekihan/traefik-mtls-authz
      version: v0.1.1
      hash: "2cc96729ae89164d5c6a73ad79601bf04efcedc0448cd93e0eb8f81465d90c23"
```

The hash pins the v0.1.1 archive downloaded from the Plugin Catalog. Update the
version and hash together when upgrading; it is not the hash of GitHub's source zip.
Then create the middleware described below and place it first on every matching
application router. The route must use `RequireAndVerifyClientCert`; see the
[deployment contract](#deployment-contract) for the required TLS and route coverage.

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

### Configuration Options

These fields belong inside the JSON object supplied as `policyJSON`.

| Option | Type | Required / default | Description |
|---|---|---|---|
| `schemaVersion` | integer | Required: `1` | Policy schema version. |
| `app` | string | Required | Non-empty application name used in logs. |
| `policyRevision` | string | `""` | Revision identifier used to trace policy changes in logs. |
| `trustedIssuers` | array of strings | Required, non-empty | SHA-256 fingerprints of verified trust-anchor DER certificates, as 64 lowercase hex characters. |
| `identityPrefix` | string | Required | Full namespace such as `urn:noqer:mtls:clients:`. |
| `identities` | array of strings | `[]` | Exact enrolled URI SAN identities allowed for this application; an empty list denies everyone. |
| `disabledIdentities` | array of strings | `[]` | Identities denied even when enrolled. |
| `blockedFingerprints` | array of objects | `[]` | Block certificates by `fingerprint`; optional `note` and `expires` fields document each block. |
| `constraints` | object | `{}` | Per-enrolled-identity `methods` and `paths` lists; both must be non-empty. |
| `stripHeaders` | boolean | `true` | Mandatory identity-header stripping; `false` is rejected. |
| `forwardIdentityHeader` | string | `""` | Optional verified identity header in the `X-Mtls-*` namespace, for example `X-Mtls-Identity`. |

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
- A pinned plugin version and catalog archive hash, or a pinned commit while loaded as a local plugin.
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

`VERSION` contains the plugin version without `v`; git tags use the `v` prefix.
See [GitHub Releases](https://github.com/zekihan/traefik-mtls-authz/releases) for release notes.
The release workflow requires unit, documentation and real-Traefik checks before
publishing a source release. The public repository needs the `traefik-plugin`
topic for catalog discovery. After catalog indexing, download the exact catalog
archive and append its SHA-256 to the release notes with
`scripts/catalog_hash.sh v0.1.1`. Operators pin that hash with the version.
Never substitute the hash of GitHub's source zip for the catalog archive hash.

## License

MIT. See [LICENSE](LICENSE).
