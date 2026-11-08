# Fuzzing campaign

Native Go fuzzing (`go test -fuzz`) of every parser and authorization decision point
in the plugin, run in November 2026. Before this campaign the repository had no
`func Fuzz` targets.

## Threat model

The attacker controls every request header, including any forwarded client-certificate
header (`X-Forwarded-Tls-Client-Cert`, `-Info`), the request line, Host and SNI, and can
present any certificate that Traefik's `RequireAndVerifyClientCert` accepted, with
arbitrary subject, SAN, URI, e-mail and extension contents. The worst bug class is
authorization bypass (a request that should be denied gets allowed). Panics, unbounded
allocation or CPU on hostile input, and accepted invalid configuration are also findings.

## Attack surface

The plugin never parses forwarded certificate headers. It reads only
`req.TLS.VerifiedChains` and `req.TLS.PeerCertificates`, and strips inbound `X-Mtls-*`
and `X-Forwarded-Tls-Client-Cert(-Info)` headers after an allow. The parsers and
decision points are:

| Code | Role |
| --- | --- |
| `parsePolicy`, `validateJSON`, `checkShape`, `validate` (policy.go, json.go) | policy transports and semantic validation |
| `rawURIIdentity` (identity.go) | raw SAN DER walk via `encoding/asn1` |
| `authorize` (authz.go) | the decision algorithm of docs/design.md section 3 |
| `ServeHTTP` header stripping (authz.go) | backend-visible header hygiene |
| `logDecision` (authz.go) | deny/allow log lines |

## Oracles

The oracles in `fuzz_ref_test.go` are written from docs/design.md, not from the
production code. They avoid the production regular expressions, `encoding/asn1` and
`encoding/json` tokenization, so a parser bug cannot be mirrored into its own oracle:

- a strict DER TLV reader and `refSAN`;
- regex-free identity, prefix, fingerprint, date, path and header-token validators;
- a strict RFC 8259 JSON reader and `refAcceptPolicy`;
- `refDecide`, a reference implementation of the design section 3 algorithm;
- `checkAllowInvariant`: an allow implies a pinned anchor, valid chain times, an
  unblocked leaf, exactly one SAN extension byte-equal to `canonicalSAN(identity)`, an
  enrolled and not disabled identity, and a satisfied constraint.

## Targets and properties

| Target | File | Properties |
| --- | --- | --- |
| `FuzzPolicyJSON` | fuzz_policy_test.go | plugin acceptance equals reference acceptance; accepted policies agree field by field and round-trip through a canonical serialization; the native `policy` transport decides like `policyJSON` (exceptions I1) |
| `FuzzPolicyFields` | fuzz_policy_test.go | one field at a time inside a valid policy, and each validator in isolation, versus the reference |
| `FuzzRawSAN` | fuzz_san_test.go | `rawURIIdentity` equals the reference DER reader with zero, one or two SAN extensions among unrelated ones; success implies the canonical encoding |
| `FuzzAuthorizeX509` | fuzz_san_test.go | real ed25519-signed certificates (`x509.CreateCertificate` then `ParseCertificate`) with fuzzed SAN bytes, CN, DNS, e-mail, URIs and extra extensions; reference decision plus the allow invariant; no CN, DNS, e-mail or alternate URI spelling of an enrolled identity is allowed |
| `FuzzAuthorizeSynthetic` | fuzz_authz_test.go | arbitrary TLS state (nil entries, peer mismatch, several chains, extreme times, inconsistent raw and parsed SANs) and random policy; exact deny-reason agreement plus the allow invariant |
| `FuzzHeaderSpoofing` | fuzz_authz_test.go | wire-parsed and raw non-canonical header keys; headers never change the decision; after an allow no header a backend could read as an identity or forwarded-cert header (case-folded, `_` treated as `-`) survives except the configured forward header carrying exactly the identity; unrelated headers are preserved |
| `FuzzConstraintRequest` | fuzz_authz_test.go | `http.ReadRequest`-parsed request lines; an allow means the literal wire path and the proxied `EscapedPath` equal an allowed path byte for byte; every accepted constraint path is reachable by its literal request |
| `FuzzDecisionLog` | fuzz_log_test.go | the deny log is exactly one line; no query, header or full fingerprint leaks; the identity field is bounded to 128 bytes plus the marker; the whole line is linear in the request size (I4); the response is the fixed 403 |

## Runs

All runs used `-parallel 4` on a 16-core Linux host with Go 1.27.3 (the toolchain
selected by go.mod), three targets at a time. Exec counts are the final counts that
`go test` reported.

| Target | Smoke | 5 min | 60 min | 120 min | Total duration | Total execs | Corpus after | Failures |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `FuzzPolicyJSON` | | 7,328,537 | 64,368,245 | 176,109,411 | 3h05m | 247,806,193 | 929 | none |
| `FuzzPolicyFields` | | 1,574,910 | 25,343,142 | 80,519,613 | 3h05m | 107,437,665 | 959 | none |
| `FuzzRawSAN` | | 11,492,764 | 105,641,945 | | 1h05m | 117,134,709 | 49 | none |
| `FuzzAuthorizeX509` | | 4,848,083 | 35,079,052 | | 1h05m | 39,927,135 | 690 | none |
| `FuzzAuthorizeSynthetic` | | 4,697,281 | 43,174,178 | | 1h05m | 47,871,459 | 804 | none |
| `FuzzHeaderSpoofing` | 1,177,349 | 5,801,266 | 60,555,114 | 156,461,256 | 3h05m30s | 223,994,985 | 430 | F1 seeds only (fixed before these runs) |
| `FuzzConstraintRequest` | | 2,625,819 | 27,087,349 | | 1h05m | 29,713,168 | 657 | none |
| `FuzzDecisionLog` | 502,589 | 4,867,618 | 49,330,273 | | 1h05m30s | 54,700,480 | 251 | none |
| **Total** | | | | | 14h47m (target-time) | **868,585,794** | | |

Smoke runs lasted 30 seconds. A 20-second run of `FuzzDecisionLog`, made after
the log-size property was added, is not counted. Each phase resumed from the cached
corpus of the previous one.

Plateau. `FuzzRawSAN` found no new coverage in its 60-minute run, and `FuzzDecisionLog`
found none after minute 30. The other 60-minute runs were still adding interesting
inputs at a decreasing rate. For example, `FuzzAuthorizeX509` reached 140, 169, 186
and 197 at 15, 30, 45 and 60 minutes. The three targets that grew fastest (both policy
targets and `FuzzHeaderSpoofing`) got another 120 minutes. There they slowed to
roughly 10 to 25 new inputs per 30 minutes. Go counts coverage-counter bucket changes
as new inputs, so this count rarely reaches exactly zero for parser-heavy targets.

The macOS session that wrote the harness also ran 45-second smoke runs of six targets
with no failures. Those runs are not counted above.

## Findings

### F1 (Medium, fixed): underscore spellings of protected headers reached the backend

- Reproducer: `testdata/fuzz/FuzzHeaderSpoofing/underscore-identity` and
  `underscore-cert-info`, which send `X_Mtls_Identity: urn:noqer:mtls:clients:root` or
  `X-Forwarded-Tls-Client-Cert_Info: ...` on an allowed request.
- Root cause: `ServeHTTP` compared lower-cased header names against `x-mtls-` and the two
  forwarded-cert names. Go's HTTP parser accepts `_` in header names, and CGI, WSGI, PHP
  and similar backends map both `-` and `_` to `_` (`HTTP_X_MTLS_IDENTITY`), so the
  underscore spelling survived stripping.
- Impact: an already-authorized client could send a forged identity or forwarded
  certificate to a backend that normalizes `_` and trusts those headers, and
  impersonate another identity there. An unauthorized client gets nothing, because the
  decision does not read headers.
- Fix: commit f3979b3, "Strip underscore spellings of protected headers". `_` is treated
  as `-` before matching. `TestHeadersAndResponseWriter` injects `X_Mtls_Identity`,
  `x_forwarded_tls_client_cert` and `X-Forwarded-Tls-Client-Cert_Info`.

No other target produced a crasher, property failure, timeout or out-of-memory error
in about 869 million executions. In particular, no input made a request allowed that
the reference algorithm denies. No policy was accepted that the reference rejects, or
the other way round, apart from the documented native-transport exceptions in I1.

### Informational (recorded, not changed)

- I1: the native `policy` transport cannot detect duplicate keys or number spellings
  (`1.0` and `1e0` become integer 1), because the provider has already decoded the map.
  `FuzzPolicyJSON` exempts exactly these two cases. `policyJSON` remains the recommended
  transport (docs/design.md).
- I2: constraint paths accept `[` and `]`, because Go's `net/url` leaves them literal in
  `EscapedPath`. RFC 3986 does not allow them in a path. This is harmless because matching
  is exact and every accepted path is reachable by its literal request. The reference
  path validator was aligned to accept them.
- I3 (open question): only `VerifiedChains[0]` is considered. With cross-signed CAs, a
  request whose first verified chain ends at an unpinned root is denied even when a later
  chain ends at a pinned one. This fails closed, so it is an availability issue and not
  a bypass. Pin every root the client chains can reach, or decide whether `authorize`
  should scan all verified chains.
- I4 (Low, log amplification): deny logs include Host, method, SNI and path without a
  length cap. Only the identity is capped, at 128 bytes, as docs/design.md section 6
  specifies. `%q` expands each non-printable byte to at most 4 bytes, so a single request
  near Traefik's 1 MiB header limit can produce a deny line of about 4 MiB at ERROR level.
  Only a client holding a certificate that Traefik verified can reach this. The growth is
  linear, and `FuzzDecisionLog` now asserts that bound. Capping these fields would be a
  design change, so it is recorded and not applied.

## Open questions

- I3: should `authorize` accept any verified chain that ends at a pinned anchor?
- I4: should request fields in deny logs be capped like the identity?

## How to rerun

Run one target at a time. `-run` keeps `-fuzz` from also running every unit test,
and `-timeout 0` disables the default 10-minute test binary deadline:

```sh
go test -run '^FuzzPolicyJSON$' -fuzz '^FuzzPolicyJSON$' -fuzztime 60m -parallel 4 -timeout 0 .
```

The target names are `FuzzPolicyJSON`, `FuzzPolicyFields`, `FuzzRawSAN`,
`FuzzAuthorizeX509`, `FuzzAuthorizeSynthetic`, `FuzzHeaderSpoofing`,
`FuzzConstraintRequest` and `FuzzDecisionLog`. Seeds and committed crashers under
`testdata/fuzz/` run on every `make test`. A new failure is written to
`testdata/fuzz/<Target>/`. Keep it as a regression entry once it is fixed or triaged.
