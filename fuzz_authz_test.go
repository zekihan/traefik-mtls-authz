package traefik_mtls_authz

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

var fuzzTimes = []time.Duration{-2 * time.Hour, -61 * time.Second, -60 * time.Second, -60*time.Second - 1, -59 * time.Second, 0, 59 * time.Second, 60 * time.Second, 60*time.Second + 1, 61 * time.Second, 2 * time.Hour}

func fuzzTime(b *fuzzBytes) time.Time {
	switch i := b.intn(len(fuzzTimes) + 3); i {
	case len(fuzzTimes):
		return time.Time{}
	case len(fuzzTimes) + 1:
		return time.Unix(1<<62, 999999999)
	case len(fuzzTimes) + 2:
		return time.Unix(-1<<62, 0)
	default:
		return testNow.Add(fuzzTimes[i])
	}
}

const (
	fuzzBob   = "urn:noqer:mtls:clients:bob"
	fuzzCarol = "urn:noqer:mtls:clients:carol"
)

// FuzzAuthorizeSynthetic drives authorize with arbitrary TLS state, including
// states crypto/tls never produces (inconsistent parsed and raw SANs, nil
// entries, mismatched peers, several chains, extreme validity times) and a
// randomly shaped policy. Properties: the deny reason equals the reference
// algorithm from docs/design.md section 3, and every allow satisfies
// checkAllowInvariant.
func FuzzAuthorizeSynthetic(f *testing.F) {
	quietFuzzLogs(f)
	f.Add([]byte{}, testIdentity, testIdentity, "GET", "https://app.test/")
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "URN:noqer:mtls:clients:alice", testIdentity, "POST", "/upload")
	f.Add([]byte{1, 0, 5, 5, 5, 5, 5, 5, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1}, fuzzBob, fuzzBob, "POST", "/insert/journald/upload")
	f.Add([]byte{3, 2, 1, 0, 5, 5, 0, 5, 5, 5, 5, 2, 2, 3, 3, 3, 3, 3}, testIdentity, "urn:noqer:mtls:clients:%61lice", "GET", "/%2f")
	f.Add([]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}, "\x30\x00", "", "", "")
	f.Fuzz(func(t *testing.T, ctrl []byte, sanText, uriText, method, target string) {
		b := &fuzzBytes{ctrl}
		raws := [][]byte{[]byte("leaf"), []byte("intermediate"), fuzzRootRaw, []byte("other"), nil}

		// Leaf certificate with independently chosen raw SAN and parsed fields.
		leaf := fuzzCert(raws[0])
		leaf.NotBefore, leaf.NotAfter = fuzzTime(b), fuzzTime(b)
		if b.flag() {
			leaf.NotBefore, leaf.NotAfter = testNow.Add(-time.Hour), testNow.Add(time.Hour)
		}
		switch b.intn(6) {
		case 0, 1:
			leaf.Extensions = []pkix.Extension{{Id: oidSAN, Value: canonicalSAN(sanText)}}
		case 2:
			leaf.Extensions = []pkix.Extension{{Id: oidSAN, Value: []byte(sanText)}}
		case 3:
			leaf.Extensions = []pkix.Extension{{Id: oidSAN, Value: canonicalSAN(testIdentity)}, {Id: oidSAN, Value: canonicalSAN(sanText)}}
		case 4:
			leaf.Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 18}, Value: canonicalSAN(sanText)}}
		}
		switch b.intn(5) {
		case 0, 1:
			if u, err := url.Parse(uriText); err == nil {
				leaf.URIs = []*url.URL{u}
			}
		case 2:
			leaf.URIs = []*url.URL{nil}
		case 3:
			u1, _ := url.Parse(sanText)
			u2, _ := url.Parse(uriText)
			leaf.URIs = []*url.URL{u1, u2}
		}
		switch b.intn(8) {
		case 0:
			leaf.DNSNames = []string{uriText}
		case 1:
			leaf.EmailAddresses = []string{uriText}
		case 2:
			leaf.IPAddresses = []net.IP{net.IPv6loopback}
		}

		chain := []*x509.Certificate{leaf}
		for n := b.intn(4); n > 0; n-- {
			switch c := b.intn(7); {
			case c < 5:
				cert := fuzzCert(raws[c])
				cert.NotBefore, cert.NotAfter = fuzzTime(b), fuzzTime(b)
				if b.flag() {
					cert.NotBefore, cert.NotAfter = testNow.Add(-time.Hour), testNow.Add(time.Hour)
				}
				chain = append(chain, cert)
			case c == 5:
				chain = append(chain, nil)
			default:
				chain = append(chain, fuzzCert(fuzzRootRaw))
			}
		}
		state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{chain}}
		switch b.intn(8) {
		case 0:
			state.PeerCertificates = []*x509.Certificate{fuzzCert(raws[b.intn(len(raws))])}
		case 1:
			state.PeerCertificates = []*x509.Certificate{nil}
		case 2:
			state.VerifiedChains = append([][]*x509.Certificate{{}}, chain)
			state.PeerCertificates = []*x509.Certificate{leaf}
		case 3:
			state.VerifiedChains = nil
			state.PeerCertificates = []*x509.Certificate{leaf}
		default:
			copied := *leaf
			state.PeerCertificates = []*x509.Certificate{&copied}
		}

		// Policy shaped from the same stream.
		trusted := []string{refFingerprint(fuzzRootRaw)}
		if b.flag() {
			trusted = []string{refFingerprint([]byte("other"))}
		}
		candidates := []string{testIdentity, fuzzBob, fuzzCarol, sanText, uriText}
		identities, disabled := []string{}, []string{}
		seen, seenDisabled := map[string]bool{}, map[string]bool{}
		for _, c := range candidates {
			if !refIdentity(c, "urn:noqer:mtls:clients:") {
				continue
			}
			if x := b.next(); x&1 == 1 && !seen[c] {
				identities, seen[c] = append(identities, c), true
			}
			if x := b.next(); x&3 == 3 && !seenDisabled[c] {
				disabled, seenDisabled[c] = append(disabled, c), true
			}
		}
		pol := map[string]interface{}{
			"schemaVersion": 1, "app": "fuzz", "trustedIssuers": trusted,
			"identityPrefix": "urn:noqer:mtls:clients:", "identities": identities, "disabledIdentities": disabled,
		}
		if b.flag() {
			pol["blockedFingerprints"] = []interface{}{map[string]interface{}{"fingerprint": refFingerprint(raws[0])}}
		}
		if len(identities) > 0 && b.flag() {
			paths := []string{"/upload"}
			if u, err := url.Parse(target); err == nil && refConstraintPath(u.Path) && u.Path != "/upload" {
				paths = append(paths, u.Path)
			}
			methods := []string{refMethods[b.intn(len(refMethods))]}
			pol["constraints"] = map[string]interface{}{identities[b.intn(len(identities))]: map[string]interface{}{"methods": methods, "paths": paths}}
		}
		h, err := New(context.Background(), http.NotFoundHandler(), &map[string]interface{}{"policy": pol}, "fuzz")
		if err != nil {
			t.Fatalf("generated policy rejected: %v %#v", err, pol)
		}
		m := h.(*Middleware)
		m.now = func() time.Time { return testNow }

		req := &http.Request{Method: method, Header: http.Header{}, TLS: state}
		if b.intn(4) != 0 {
			req.URL, _ = url.Parse(target)
		}
		d := m.authorize(req)
		rp := refPolicyFromParsed(m.policy)
		if want := refDecide(rp, req, testNow); d.reason != want {
			t.Fatalf("plugin=%s reference=%s", d.reason, want)
		}
		checkAllowInvariant(t, rp, req, testNow, d)
	})
}

// fuzzAllowMiddleware enrolls alice (the fixture identity of validRequest).
func fuzzAllowMiddleware(t *testing.T, forward string, constraints map[string]interface{}, next http.Handler) *Middleware {
	t.Helper()
	if next == nil {
		next = http.NotFoundHandler()
	}
	cfg := validConfig()
	p := (*cfg)["policy"].(map[string]interface{})
	p["forwardIdentityHeader"] = forward
	if constraints != nil {
		p["constraints"] = constraints
	}
	h, err := New(context.Background(), next, cfg, "fuzz")
	if err != nil {
		t.Fatal(err)
	}
	m := h.(*Middleware)
	m.now = func() time.Time { return testNow }
	return m
}

// protectedHeader reports whether a backend could read key as one of the
// identity headers the plugin promises to strip. Backends commonly fold case
// and, through CGI/WSGI/PHP-style environment variables, treat '_' and '-' as
// the same character (HTTP_X_MTLS_IDENTITY).
func protectedHeader(key string) bool {
	n := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	return strings.HasPrefix(n, "x-mtls-") || n == "x-forwarded-tls-client-cert" || n == "x-forwarded-tls-client-cert-info"
}

// FuzzHeaderSpoofing sends attacker-chosen request headers, both through
// Go's HTTP/1 request parser (what Traefik receives on the wire) and as raw
// non-canonical map keys (what an earlier middleware could produce).
// Properties: headers never change the authorization decision; after an allow
// the backend sees no header it could interpret as an identity or forwarded
// certificate header except the configured forward header carrying exactly
// the verified identity; unrelated headers are preserved unchanged.
func FuzzHeaderSpoofing(f *testing.F) {
	quietFuzzLogs(f)
	f.Add("X-Mtls-Identity: urn:noqer:mtls:clients:root\nX-Forwarded-Tls-Client-Cert: MIIB\n", byte(0))
	f.Add("x-mtls-identity: a\nX-MTLS-IDENTITY: b\nX-Keep: kept\n", byte(1))
	f.Add("X-Forwarded-Tls-Client-Cert: a\nX-Forwarded-Tls-Client-Cert: b\n", byte(5))
	f.Add("x-mtls-custom-identity: spoof\nX-Mtls-Custom-Identity: spoof2\n", byte(6))
	f.Add("X-Mtls-Identity: a\r\n b\n", byte(9))
	f.Fuzz(func(t *testing.T, raw string, ctrl byte) {
		forward := []string{"", "X-Mtls-Identity", "x-mtls-custom-identity"}[int(ctrl)%3]
		var req *http.Request
		if ctrl&4 == 0 {
			var err error
			req, err = http.ReadRequest(bufio.NewReader(strings.NewReader("GET /path HTTP/1.1\r\nHost: app.test\r\n" + raw + "\r\n\r\n")))
			if err != nil {
				t.Skip()
			}
		} else {
			req = httptest.NewRequest("GET", "https://app.test/path", nil)
			for _, line := range strings.Split(raw, "\n") {
				key, value, ok := strings.Cut(line, ":")
				if ok && refHeaderToken(key) {
					req.Header[key] = append(req.Header[key], value)
				}
			}
		}
		valid := validRequest()
		req.TLS = valid.TLS
		if ctrl&8 != 0 {
			req.TLS = &tls.ConnectionState{PeerCertificates: valid.TLS.PeerCertificates}
		}
		original := req.Header.Clone()

		var seen http.Header
		reached := false
		m := fuzzAllowMiddleware(t, forward, nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			reached, seen = true, r.Header.Clone()
		}))
		bare := req.Clone(context.Background())
		bare.Header = http.Header{}
		want := m.authorize(bare)
		if got := m.authorize(req); got != want {
			t.Fatalf("headers changed the decision: with=%+v without=%+v", got, want)
		}
		w := httptest.NewRecorder()
		m.ServeHTTP(w, req)
		if reached != (want.reason == "allowed") || (!reached && w.Code != http.StatusForbidden) {
			t.Fatalf("reached=%v reason=%s status=%d", reached, want.reason, w.Code)
		}
		if !reached {
			return
		}
		forwarded := 0
		for key, values := range seen {
			if !protectedHeader(key) {
				continue
			}
			if forward != "" && strings.EqualFold(key, forward) && len(values) == 1 && values[0] == want.identity {
				forwarded++
				continue
			}
			t.Fatalf("spoofable identity header %q=%q reached the backend", key, values)
		}
		if (forward != "") != (forwarded == 1) {
			t.Fatalf("forward header %q present %d times", forward, forwarded)
		}
		for key, values := range original {
			if protectedHeader(key) {
				continue
			}
			if got := seen[key]; strings.Join(got, "\x00") != strings.Join(values, "\x00") || len(got) != len(values) {
				t.Fatalf("unrelated header %q changed: %q -> %q", key, values, got)
			}
		}
	})
}

// FuzzConstraintRequest parses attacker-chosen request lines with Go's HTTP/1
// parser and authorizes them against a constrained identity. Properties:
// reference decision agreement; an allow means the literal wire path and the
// path the reverse proxy forwards both equal an allowed path byte-for-byte
// (no encoded or normalized alias); every accepted constraint path is
// reachable by its own literal request (no unsatisfiable policy accepted).
func FuzzConstraintRequest(f *testing.F) {
	quietFuzzLogs(f)
	for _, target := range []string{"/insert/journald/upload", "/insert%2Fjournald/upload", "/insert/journald/%75pload", "/insert/journald/upload?x=1", "https://app.test/insert/journald/upload", "/insert/journald/upload/", "//insert/journald/upload", "/insert/./journald/upload", "*", "/insert/journald/upload;x", "/insert/journald/upload#f", "/INSERT/journald/upload", "http:/insert/journald/upload", "HTTPS://app.test/insert/journald/upload"} {
		f.Add("POST", target, "/insert/journald/upload", byte(0))
	}
	f.Add("GET", "/a[b]", "/a[b]", byte(1))
	f.Add("GET", "/a!b", "/a!b", byte(1))
	f.Add("GET", "/", "/", byte(2))
	f.Add("get", "/", "/", byte(2))
	f.Fuzz(func(t *testing.T, method, target, allowed string, ctrl byte) {
		methods := [][]string{{"POST"}, {"GET"}, {"GET", "POST", "PUT"}}[int(ctrl)%3]
		paths := []string{"/insert/journald/upload"}
		if refConstraintPath(allowed) && allowed != paths[0] {
			paths = append(paths, allowed)
		}
		rule := map[string]interface{}{"methods": methods, "paths": paths}
		m := fuzzAllowMiddleware(t, "", map[string]interface{}{testIdentity: rule}, nil)
		rp := refPolicyFromParsed(m.policy)

		// Every accepted path must be reachable by its literal request.
		for _, p := range paths {
			req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(methods[0] + " " + p + " HTTP/1.1\r\nHost: app.test\r\n\r\n")))
			if err != nil {
				t.Fatalf("accepted constraint path %q is not a valid request target: %v", p, err)
			}
			req.TLS = validRequest().TLS
			if d := m.authorize(req); d.reason != "allowed" {
				t.Fatalf("accepted constraint path %q is unsatisfiable: %s", p, d.reason)
			}
		}

		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(method + " " + target + " HTTP/1.1\r\nHost: app.test\r\n\r\n")))
		if err != nil {
			t.Skip()
		}
		req.TLS = validRequest().TLS
		d := m.authorize(req)
		if want := refDecide(rp, req, testNow); d.reason != want {
			t.Fatalf("plugin=%s reference=%s", d.reason, want)
		}
		checkAllowInvariant(t, rp, req, testNow, d)
		if d.reason != "allowed" {
			return
		}
		wire := wirePath(target)
		proxied := (&url.URL{Path: req.URL.Path, RawPath: req.URL.RawPath}).EscapedPath()
		okWire, okProxy := false, false
		for _, p := range paths {
			okWire = okWire || p == wire
			okProxy = okProxy || p == proxied
		}
		if !okWire || !okProxy {
			t.Fatalf("allowed %s %q: wire path %q / proxied path %q not an exact allowed path %q", method, target, wire, proxied, paths)
		}
	})
}

// wirePath returns the literal path component of an origin-form or
// absolute-form request target (RFC 3986 section 3), without decoding.
func wirePath(target string) string {
	wire, _, _ := strings.Cut(target, "?")
	if colon := strings.IndexByte(wire, ':'); colon > 0 {
		scheme, valid := wire[:colon], true
		for i := 0; i < len(scheme); i++ {
			c := scheme[i]
			alpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
			valid = valid && (alpha || (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')))
		}
		if valid {
			wire = wire[colon+1:]
			if strings.HasPrefix(wire, "//") {
				if slash := strings.IndexByte(wire[2:], '/'); slash >= 0 {
					wire = wire[2+slash:]
				} else {
					wire = ""
				}
			}
		}
	}
	return wire
}
