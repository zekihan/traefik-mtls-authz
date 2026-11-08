package traefik_mtls_authz

import (
	"crypto/x509/pkix"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// FuzzDecisionLog feeds attacker-controlled request fields (method, Host,
// path, query, SNI) and certificate URI bytes into a denied request.
// Properties: the deny log is exactly one line; the query string, request
// headers and full fingerprints never appear; the identity field is bounded to
// 128 bytes plus the truncation marker; the whole line is linear in the
// request size; the response is the fixed 403.
func FuzzDecisionLog(f *testing.F) {
	quietFuzzLogs(f)
	f.Add("GET", "app.test", "/path", "secret=1", "app.test", testIdentity)
	f.Add("GET\n", "host\nforged=line", "/path\r\nevent=allow", "a=b\nc", "sni\x00", "urn:noqer:mtls:clients:\n"+strings.Repeat("a", 200))
	f.Add(" ", "\xff\xfe", "/\"quoted\"", "", "", "urn:noqer:mtls:clients:é")
	f.Fuzz(func(t *testing.T, method, host, path, query, sni, identity string) {
		const marker = "QSECRETQ"
		if strings.Contains(method+host+path+sni+identity, marker) {
			t.Skip()
		}
		m := fuzzAllowMiddleware(t, "", nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Fatal("denied request reached next")
		}))
		m.identities = map[string]bool{} // force a deny after identity extraction
		req := validRequest()
		req.Method, req.Host = method, host
		req.URL = &url.URL{Path: path, RawQuery: marker + query}
		req.TLS.ServerName = sni
		leaf := req.TLS.PeerCertificates[0]
		leaf.URIs[0] = &url.URL{Opaque: identity}
		leaf.Extensions = []pkix.Extension{{Id: oidSAN, Value: canonicalSAN(identity)}}
		req.Header.Set("X-Header-Marker", marker)
		var buffer strings.Builder
		saved := decisionLogger.Writer()
		decisionLogger.SetOutput(&buffer)
		defer decisionLogger.SetOutput(saved)
		w := httptest.NewRecorder()
		m.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || w.Body.String() != "forbidden\n" {
			t.Fatalf("status=%d body=%q", w.Code, w.Body.String())
		}
		line := buffer.String()
		if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
			t.Fatalf("deny log is not exactly one line: %q", line)
		}
		if strings.Contains(line, marker) {
			t.Fatalf("query or header leaked into log: %q", line)
		}
		if strings.Contains(line, refFingerprint([]byte("leaf"))) || strings.Contains(line, refFingerprint([]byte("root"))) {
			t.Fatal("full fingerprint logged")
		}
		start := strings.Index(line, " identity=")
		end := strings.Index(line, " leafFp=")
		if start < 0 || end < start {
			t.Fatalf("missing identity field: %q", line)
		}
		quoted := line[start+len(" identity=") : end]
		if len(quoted) > 4*128+len(`"[truncated]"`)+2 {
			t.Fatalf("identity log field unbounded: %d bytes", len(quoted))
		}
		// Host, path, method and SNI are deliberately not truncated (design
		// section 6); %q may expand each byte to at most 4 bytes, so the line
		// stays linear in the attacker-controlled request size.
		if bound := 4*(len(method)+len(host)+len(path)+len(sni)+128+len("[truncated]")) + 1024; len(line) > bound {
			t.Fatalf("deny log grew superlinearly: %d bytes > %d", len(line), bound)
		}
	})
}
