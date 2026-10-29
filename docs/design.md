# Design: per-application mTLS authorization

Status: design only (2026-10-30). Nothing below is implemented; v0.1.0 denies every request.
Target runtime: Traefik v3.7.14 (yaegi v0.16.1, Go 1.26 module), Go standard library only, no generics.
Deployment, GitOps policy distribution, PKI, DNS and migration details live in the argocd repository.

## 1. Boundaries

Native Traefik does all cryptography. A TLSOption with `clientAuth.clientAuthType: RequireAndVerifyClientCert`
builds and verifies the chain, checks the validity window and the clientAuth EKU, and pools every CA PEM from
`secretNames` into `ClientCAs` (`pkg/tls/tlsmanager.go`, `buildTLSConfig`).

The plugin is a pure authorization filter over `req.TLS.VerifiedChains` and its own middleware configuration.

In scope: verified-TLS evidence, trust-anchor pin, per-request validity re-check, fingerprint blocklist,
single-URI-SAN identity extraction, disabled-identity list, per-app allowlist, optional per-identity
method/path constraints, inbound identity-header stripping, deny logging.

Out of scope: PEM parsing, key material, signature verification, CRL/OCSP, sessions, cookies, redirects,
header-based identity, request bodies, network or disk I/O at request time, state shared between
middleware instances, metrics registration (not possible from a yaegi plugin).

## 2. Verified runtime facts the design depends on

| # | Fact | Source (Traefik v3.7.14 unless noted) |
|---|------|------|
| R1 | Plugin config is decoded with mapstructure, `WeaklyTypedInput: true`, a comma string-to-slice hook and no unknown-key rejection. Misspelled keys vanish silently; `"yes"` becomes `true`. | `pkg/plugins/middlewareyaegi.go:88-108` |
| R2 | If `New` returns an error, or the Middleware is missing or malformed, the router is not registered and Traefik answers 404. The host's TLS option is still installed, so the client certificate is still demanded first. | `pkg/server/middleware/middlewares.go:73,476`, `pkg/server/router/router.go:262-265` |
| R3 | With `experimental.abortOnPluginFailure`, a plugin that fails to download or parse makes Traefik exit. Without it, every plugin middleware is disabled and routers referencing one fall under R2. | `cmd/traefik/traefik.go:255-262` |
| R4 | Every TLS router gets an automatic SNI check: the TLS option chosen by SNI must equal the router's option, otherwise 421 before any middleware runs. | `pkg/server/router/router.go:383-386`, `pkg/middlewares/snicheck` |
| R5 | When one host is served by routers with different TLS options, all of them silently fall back to the **default** options unless `core.strictTLSOptions=true`. In that case no client certificate is requested and `VerifiedChains` is empty. | `pkg/server/aggregator.go:192-321` |
| R6 | `VerifiedChains` is set on the server only for `VerifyClientCertIfGiven` with a certificate or `RequireAndVerifyClientCert`. `PeerCertificates` may be set without verification. | Go `crypto/tls/common.go:283-304` |
| R7 | On session resumption Go restores `PeerCertificates` and `VerifiedChains` from the ticket, after re-checking presence, `NotAfter`, and that a stored chain still verifies against the current `ClientCAs` with the clientAuth EKU. With `SessionTicketsDisabled` there is no resumption in TLS 1.2 or 1.3. Tickets live at most 7 days; keys rotate every 24h per process. | Go 1.27 `handshake_server_tls13.go:295,362-428`, `handshake_server.go:450,508-549`, `common.go:970,998` |
| R8 | An established keep-alive connection is never re-validated by TLS. Expiry after the handshake is invisible to Traefik. | Go `crypto/tls` (no post-handshake checks) |
| R9 | yaegi v0.16.1 exports `tls.ConnectionState`, `x509.Certificate`, `x509.ParseCertificate`, `x509.VerifyOptions`, `x509.CertPool`, `crypto/sha256`, `encoding/pem`. The plugin receives the real `*http.Request` through reflection, so `req.TLS` is the live connection state. | `yaegi/stdlib/go1_22_crypto_tls.go`, `go1_22_crypto_x509.go`, `middlewareyaegi.go:66-78` |
| R10 | Plugin `os.Stdout` is logged at DEBUG and `os.Stderr` at ERROR. Stdout-only logging is invisible at INFO. | `middlewareyaegi.go:139-142` |
| R11 | `experimental.plugins.<name>.hash` is the SHA-256 of the downloaded archive; Traefik refuses a mismatch. | `pkg/plugins/manager.go:80-95,341-357` |

Not yet verified, and therefore acceptance criteria (section 9): that the field reads and SHA-256 in section 3
execute under yaegi inside Traefik v3.7.14 (A1), and the resumption cases A2 and A3.

## 3. Request authorization algorithm

Per request. No body access. The handler never wraps the ResponseWriter, so `http.Hijacker` (WebSockets) and
`http.Flusher` (streams) pass through to the next handler untouched.

1. `req.TLS == nil` -> deny `no_tls`.
2. `len(req.TLS.VerifiedChains) == 0` -> deny `unverified`. Covers weaker client-auth modes, the default-option
   fallback (R5) and any proxy that terminates the client's TLS in front of Traefik.
3. `leaf := VerifiedChains[0][0]`; require `bytes.Equal(leaf.Raw, PeerCertificates[0].Raw)` -> else `unverified`.
4. `anchor := VerifiedChains[0][len-1]`; `hex(sha256(anchor.Raw))` must be in `trustedIssuers` -> else
   `issuer_not_trusted`. Defense in depth against a wrong TLSOption or CA bundle on the route.
5. `now` must satisfy `NotBefore-60s <= now <= NotAfter+60s` -> else `cert_time` (needed because of R8).
6. `hex(sha256(leaf.Raw))` in `blockedFingerprints` -> deny `fingerprint_blocked`.
7. Identity: exactly one entry in `leaf.URIs` and none in `DNSNames`, `EmailAddresses`, `IPAddresses`.
   The URI string must match `^urn:noqer:mtls:[a-z0-9]+(-[a-z0-9]+)*:[a-z0-9]([-a-z0-9]*[a-z0-9])?$`,
   be at most 128 bytes and start with `identityPrefix`. Zero URIs -> `identity_missing`; more than one, or
   extra SAN types -> `identity_ambiguous`; bad syntax or prefix -> `identity_invalid`.
   Comparison is exact bytes; no case folding, no normalization.
8. Identity in `disabledIdentities` -> deny `identity_disabled`.
9. Identity not in `identities` -> deny `not_enrolled`.
10. If `constraints[identity]` exists: `req.Method` must be listed and `req.URL.Path` must equal one listed
    path exactly -> else `constraint_method` / `constraint_path`.
11. Delete inbound `X-Forwarded-Tls-Client-Cert`, `X-Forwarded-Tls-Client-Cert-Info` and every `X-Mtls-*`
    header. If `forwardIdentityHeader` is set, set that header to the identity.
12. `next.ServeHTTP(rw, req)`.

Authorization happens once per HTTP request. A WebSocket is authorized at its Upgrade request; a streaming
upload at its first byte of headers. The plugin cannot close hijacked connections; policy changes apply to the
next request on any connection, not to streams already in flight.

CN and other subject fields are never consulted. Every deny is HTTP 403 with body `forbidden`,
`Cache-Control: no-store` and `X-Mtls-Authz-Reason: <code>`. No redirect, no HTML.

## 4. Identity rules

- One leaf = one identity = one URI SAN of the form `urn:noqer:mtls:<profile>:<name>`.
- `identityPrefix` (for example `urn:noqer:mtls:clients:`) ties the identity namespace to the pinned CA.
  Every configured identity and constraint key must start with it; the plugin rejects the policy otherwise.
- Renewal keeps the URI and changes the key and fingerprint; the policy is keyed by URI, so renewals need no
  policy change. Blocking is per certificate (fingerprint); disabling is per identity.

## 5. Configuration

`Config` has one field, `policy`, typed `map[string]any`. `New` re-encodes it to JSON and decodes with
`json.Decoder.DisallowUnknownFields` into the typed policy. This turns R1's silent key dropping and weak typing
into a load error, which Traefik converts into a 404 for the route (R2). Cost: one extra nesting level in YAML,
and `.traefik.yml` `testData` must hold a complete valid policy because the plugin catalog loads it.

```go
// Shape only. No generics, stdlib only.
type Config struct {
	Policy map[string]any `json:"policy"`
}

type policy struct {
	SchemaVersion         int                   `json:"schemaVersion"`         // must be 1
	App                   string                `json:"app"`                   // non-empty, logged
	PolicyRevision        string                `json:"policyRevision"`        // opaque, logged at load
	TrustedIssuers        []string              `json:"trustedIssuers"`        // 64 lowercase hex, SHA-256 of CA DER, non-empty, unique
	IdentityPrefix        string                `json:"identityPrefix"`        // e.g. "urn:noqer:mtls:clients:"
	Identities            []string              `json:"identities"`            // exact URIs, unique; empty denies everyone and logs loudly
	DisabledIdentities    []string              `json:"disabledIdentities"`    // exact URIs, unique
	BlockedFingerprints   []blockedFingerprint  `json:"blockedFingerprints"`   // SHA-256 of leaf DER
	Constraints           map[string]constraint `json:"constraints"`           // key = identity URI
	StripHeaders          *bool                 `json:"stripHeaders"`          // default true; explicit false is rejected
	ForwardIdentityHeader string                `json:"forwardIdentityHeader"` // "" = off
}

type blockedFingerprint struct {
	Fingerprint string `json:"fingerprint"` // 64 lowercase hex
	Note        string `json:"note"`        // free text
	Expires     string `json:"expires"`     // YYYY-MM-DD, informational (prune after leaf NotAfter)
}

type constraint struct {
	Methods []string `json:"methods"` // uppercase standard methods
	Paths   []string `json:"paths"`   // absolute, exact, no trailing slash, no "//", no ".."
}
```

`New` returns an error (fail closed) on: schema version other than 1; empty `app`, `trustedIssuers` or
`identityPrefix`; any malformed fingerprint or identity; duplicates in any list; an identity or constraint key
outside `identityPrefix`; a constraint with an empty method or path list; an unknown key or wrong type anywhere;
a `policy` that is absent or empty. `New` must not perform network or filesystem access.

Example dynamic configuration (Kubernetes Middleware shown; the file provider form is identical under
`http.middlewares.<name>.plugin.traefik-mtls-authz`):

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: mtls-authz
  namespace: sonarr
spec:
  plugin:
    traefik-mtls-authz:
      policy:
        schemaVersion: 1
        app: sonarr
        policyRevision: "1-3f9c2a1b"
        trustedIssuers:
          - "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        identityPrefix: urn:noqer:mtls:clients:
        identities:
          - urn:noqer:mtls:clients:z-mac
          - urn:noqer:mtls:clients:z-arch
          - urn:noqer:mtls:clients:gatus-cluster-1
        disabledIdentities: []
        blockedFingerprints:
          - fingerprint: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
            note: "z-mac leaf lost 2026-11-02"
            expires: "2027-10-28"
        constraints: {}
        stripHeaders: true
        forwardIdentityHeader: ""
```

A journald-style policy adds a constraint:

```yaml
        identities:
          - urn:noqer:mtls:clients:oci-micro-1
        constraints:
          urn:noqer:mtls:clients:oci-micro-1:
            methods: [POST]
            paths: [/insert/journald/upload]
```

## 6. Logging

Allow decisions go to `os.Stdout` (DEBUG, R10). Every deny and every `New` outcome goes to `os.Stderr`
(visible at INFO) as one `key=value` line: `event`, `reason`, `app`, `policyRevision`, `router` (the middleware
name Traefik passes to `New`), `identity` when parsed, `leafFp` and `anchorFp` (first 16 hex), `tlsVersion`,
`sni`, `host`, `method`, `path`. Never certificate bodies, never full headers.

Traefik's access log already records `TLSClientSubject` and the router name, and a 403 from the plugin is
counted in `traefik_router_requests_total`. That is the metrics path.

## 7. Deployment contract (what the plugin assumes; enforced outside this repo)

- The route's TLSOption uses `RequireAndVerifyClientCert` with the intended CA bundle; `sniStrict: true`;
  session tickets disabled (decision D5, kept so R7 and R8 are the only connection-state cases).
- `core.strictTLSOptions=true`, so a host served with conflicting options is disabled instead of silently
  falling back (R5). The plugin denies `unverified` in the fallback case regardless.
- Exactly one `mtls-authz` Middleware per application, listed **first** in the router's middleware chain.
- Every route that uses an mTLS TLSOption references its `mtls-authz` Middleware. Traefik cannot detect a
  route that merely omits the middleware; that route is open to every CA-valid certificate.
- The global parts of the policy (`trustedIssuers`, `identityPrefix`, `disabledIdentities`,
  `blockedFingerprints`) are identical in every Middleware; `policyRevision` makes drift visible in logs.
- `experimental.abortOnPluginFailure: true` and a pinned `hash` (R3, R11).
- Nothing terminates the client's TLS in front of Traefik on these routes.

## 8. Known limits

- No revocation protocol. The blocklist and CA withdrawal are the only revocation mechanisms.
- Withdrawal does not terminate established WebSockets or in-flight uploads; the operator must close the
  connection (Traefik restart or backend stop).
- A certificate that expires mid-connection is denied on its next request (step 5), not mid-stream.
- The reason header leaks the deny category to a holder of a CA-valid certificate. Accepted for operability.

## 9. Tests and acceptance criteria

Unit (stdlib, `go test -race`): one table case per deny code; forged identity headers; `req.TLS` nil;
`PeerCertificates` set with empty `VerifiedChains`; leaf/peer mismatch; wrong anchor; expired and not-yet-valid
with skew edges; blocked; disabled; not enrolled; zero and two URI SANs; URI plus DNS SAN; prefix mismatch;
constraint method and path, including `/insert/journald/upload/` and `/insert/journald/upload/extra`;
header stripping and optional forward header; `New` rejects unknown keys, weak types, duplicates, empty
issuers, bad paths; the next handler still sees `http.Hijacker` and `http.Flusher` on the ResponseWriter;
concurrent requests against one handler.

Real-Traefik integration (docker compose modeled on `traefik-real-ip/testing`, `traefik:v3.7.14` by digest,
source mounted at `/plugins-local/src/github.com/zekihan/traefik-mtls-authz`, file provider with a
`RequireAndVerifyClientCert` TLSOption, test CA and leaves generated per run, never checked in):

- no certificate and wrong CA fail the handshake;
- valid but unenrolled identity -> 403 with the reason header; enrolled -> 200;
- two URI SANs -> 403; URI plus DNS SAN -> 403;
- blocked fingerprint -> 403; disabled identity -> 403; expired leaf -> handshake failure;
- SNI/Host across different TLS options -> 421; across the same option -> routed and authorized per app;
- TLS 1.2 and TLS 1.3;
- resumed session with tickets enabled (`openssl s_client -sess_out/-sess_in`) -> same decision (A2);
- tickets disabled -> no ticket issued, full handshake (A3);
- WebSocket upgrade allowed and denied; chunked streaming POST allowed;
- policy change while a WebSocket is open -> stream survives, next request denied;
- broken plugin directory -> Traefik exits with `abortOnPluginFailure`; missing Middleware and malformed
  policy -> 404;
- stderr deny lines present at Traefik log level INFO.

Acceptance before any production route: A1 (field reads and SHA-256 execute under yaegi in v3.7.14),
A2, A3, A4 (both TLS versions), A5 (PROXY protocol v2 path leaves `req.TLS` intact) all pass in CI.

## 10. Release and catalog requirements

Delivery is through the Traefik Plugin Catalog (decision D1): public repository, `traefik-plugin` topic,
`.traefik.yml` with a complete valid `testData` policy, `go.mod`, git tags, dependencies vendored (none
planned). The catalog polls GitHub daily and opens an issue in the repository when a check fails; close it
after fixing. Operators pin `version` and `hash` (R11). Record the archive hash in the release notes.

## 11. Decisions recorded

| # | Decision | Effect here |
|---|---|---|
| D1 | Plugin catalog delivery | Section 10; `testData` must be a full policy |
| D2 | Strict `policy:` map with unknown-key rejection | Section 5 |
| D5 | Session tickets stay disabled on the TLSOption | R7/R8 are the only connection-state cases; per-request checks still required |
| D9 | No identity header forwarded by default | `forwardIdentityHeader: ""` |
