# Real Traefik acceptance tests

Run `make test/integration` on Linux with Docker Engine and Compose v2. This runs
Traefik v3.7.14 pinned by digest, with the repository mounted as a local Yaegi plugin
and a file-provider configuration. The backend is an in-process Go HTTP server;
Compose uses host networking to reach it. All entrypoints bind loopback on ephemeral
ports. No Docker socket is mounted into Traefik.

Each fixture generates a root, intermediate, server and client certificates with
temporary private keys. Cleanup stops its Compose project and removes the fixture
directory even after an assertion fails. `testing/artifacts/*.log` contains Traefik
logs for each test; the JSON-file fixture also saves `*.log.json`. These files are
ignored by git. There are no saved private keys
or TLS session tickets. The entire suite usually takes about 80–90 seconds because
one test waits for CA expiry plus the required 60-second skew allowance.

The suite checks:

- A1: strict JSON transport through Traefik's actual file provider, with unknown
  outer/nested keys, wrong scalar types, list/string/null policies rejected. Each
  rejection transitions from a working router so an old failure cannot mask a bug.
- A2: TLS 1.2 and 1.3 resumed connections with tickets enabled, for both allowed and
  denied identities. Go's real TLS client asserts `DidResume` and identical decisions;
  its session cache is also checked. This replaces the design's proposed OpenSSL
  session-file probe with direct runtime assertions and no persistent ticket files.
- A3: with tickets disabled, no cached ticket and no resumption on either TLS version.
- A4: authorization and TLS failures on both TLS 1.2 and TLS 1.3. HTTP/2 cases
  assert ALPN `h2`, the actual response protocol and TLS version, allowed/denied
  identities, raw SAN rejection and backend header stripping with/without forwarding.
- A5: a binary PROXY protocol v2 preface before ClientHello preserves verified TLS state.
- Enrolled, unenrolled, malformed and ambiguous identities, missing identity,
  raw uppercase schemes denied despite Go normalization, extra registeredID and
  unknown GeneralName SAN entries denied, fingerprint blocks and disabled identities; forged headers stripped at the backend.
- Exact method/path constraints, encoded separators denied, and unreserved encodings
  normalized identically for authorization and the backend. `%75pload` and
  dot-segment cases assert the backend's exact `X-Test-Backend-URI`. Wrong CA, expired leaf
  and missing client certificate are rejected at TLS.
- SNI/Host mismatch with different TLS options (421), and separate authorization for
  hosts sharing an option.
- Failed and missing middleware with/without a default catch-all, the same-option
  alternate-router bypass, strict TLS-option conflicts, invalid non-Host catch-all,
  and the non-strict conflict fallback (including its unauthenticated alternate).
- Middleware load failure exits Traefik with `abortOnPluginFailure`, for both a
  missing manifest and an isolated source fixture that fails Yaegi compilation.
- Allowed/denied WebSocket upgrades, reload while a WebSocket stays open, chunked
  upload delivery before EOF, and flushed responses before the stream ends.
- Intermediate expiry on the next request over the **same** established connection.
- Deny/load lines through Traefik's ERROR logger (including metadata and JSON/file
  destinations), no raw-console copies with a file sink, and DEBUG-only allow lines.

Unit tests supplement these with every certificate's validity/skew edges, issuer
pin failures, defensive malformed TLS state, all policy rules, immutable policy
snapshots, concurrent requests and ResponseWriter/body transparency. Typos in
constraint identity keys are rejected; invalid identity log values are bounded.
CI's `make tidy` and `make lint` also format/vet the integration-tagged Go file.

The suite does not publish a release or deploy to Kubernetes. Actual deployment
route coverage and consistency checks belong in the argocd repository. The catalog
testData is also loaded in real Traefik; `make check/docs` checks metadata/example
shape. Live catalog discovery follows tagging
and is outside the local runtime fixture.

Native-object policies are tested directly in Go and rejected through the file
provider. Successful native-object loading via Kubernetes CRDs is not tested;
`policyJSON` is recommended in every deployment example. Session-resumption tests
cover unchanged policy; post-resumption CA withdrawal/expiry remains native TLS
behavior outside that matrix, with session tickets disabled by the deployment
contract. The ephemeral port helper releases its reservation before Compose binds;
a concurrent host process could theoretically take that port and fail a fixture.
Hosted CI results require pushing this change.

Header stripping covers initial HTTP headers, not trailers populated while reading
the body. Trailer filtering would require a separate body-processing design;
backends must never treat trailer fields as authenticated identity.
