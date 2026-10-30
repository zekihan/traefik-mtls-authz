package traefik_mtls_authz

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testIdentity = "urn:noqer:mtls:clients:alice"

var testNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

func validConfig() *map[string]interface{} {
	cfg := map[string]interface{}{"policy": map[string]interface{}{
		"schemaVersion": 1, "app": "test", "policyRevision": "rev-1",
		"trustedIssuers": []string{fingerprint([]byte("root"))},
		"identityPrefix": "urn:noqer:mtls:clients:", "identities": []string{testIdentity},
	}}
	return &cfg
}

func newTestMiddleware(t *testing.T, cfg *map[string]interface{}, next http.Handler) *Middleware {
	t.Helper()
	if next == nil {
		next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	}
	handler, err := New(context.Background(), next, cfg, "test@file")
	if err != nil {
		t.Fatal(err)
	}
	m := handler.(*Middleware)
	m.now = func() time.Time { return testNow }
	return m
}

func validRequest() *http.Request {
	uri, _ := url.Parse(testIdentity)
	leaf := &x509.Certificate{Raw: []byte("leaf"), Extensions: []pkix.Extension{testSAN(testIdentity)}, URIs: []*url.URL{uri}, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour)}
	intermediate := &x509.Certificate{Raw: []byte("intermediate"), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	root := &x509.Certificate{Raw: []byte("root"), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}
	req := httptest.NewRequest("GET", "https://app.test/", nil)
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, ServerName: "app.test", PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, intermediate, root}}}
	return req
}

func TestAuthorization(t *testing.T) {
	cases := []struct {
		name, reason string
		change       func(*http.Request, map[string]interface{})
	}{
		{"allow", "", func(*http.Request, map[string]interface{}) {}},
		{"no-tls", "no_tls", func(r *http.Request, _ map[string]interface{}) { r.TLS = nil }},
		{"peers-only", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.VerifiedChains = nil }},
		{"empty-chain", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.VerifiedChains[0] = nil }},
		{"missing-peer", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.PeerCertificates = nil }},
		{"nil-peer", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.PeerCertificates[0] = nil }},
		{"nil-chain-cert", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.VerifiedChains[0][1] = nil }},
		{"empty-der", "unverified", func(r *http.Request, _ map[string]interface{}) { r.TLS.VerifiedChains[0][1].Raw = nil }},
		{"peer-mismatch", "unverified", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates = []*x509.Certificate{{Raw: []byte("other")}}
		}},
		{"wrong-anchor", "issuer_not_trusted", func(r *http.Request, _ map[string]interface{}) { r.TLS.VerifiedChains[0][2].Raw = []byte("wrong") }},
		{"blocked", "fingerprint_blocked", func(_ *http.Request, p map[string]interface{}) {
			p["blockedFingerprints"] = []map[string]interface{}{{"fingerprint": fingerprint([]byte("leaf")), "expires": "2000-01-01"}}
		}},
		{"no-uri", "identity_missing", func(r *http.Request, _ map[string]interface{}) { r.TLS.PeerCertificates[0].URIs = nil }},
		{"two-uris", "identity_ambiguous", func(r *http.Request, _ map[string]interface{}) {
			c := r.TLS.PeerCertificates[0]
			c.URIs = append(c.URIs, c.URIs[0])
		}},
		{"dns", "identity_ambiguous", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates[0].DNSNames = []string{"app.test"}
		}},
		{"email", "identity_ambiguous", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates[0].EmailAddresses = []string{"a@test"}
		}},
		{"ip", "identity_ambiguous", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates[0].IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}},
		{"nil-uri", "identity_invalid", func(r *http.Request, _ map[string]interface{}) { r.TLS.PeerCertificates[0].URIs[0] = nil }},
		{"prefix", "identity_invalid", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates[0].URIs[0], _ = url.Parse("urn:noqer:mtls:other:alice")
		}},
		{"syntax", "identity_invalid", func(r *http.Request, _ map[string]interface{}) {
			r.TLS.PeerCertificates[0].URIs[0], _ = url.Parse("urn:noqer:mtls:clients:Alice")
		}},
		{"disabled", "identity_disabled", func(_ *http.Request, p map[string]interface{}) { p["disabledIdentities"] = []string{testIdentity} }},
		{"unenrolled", "not_enrolled", func(_ *http.Request, p map[string]interface{}) { p["identities"] = []string{} }},
		{"method", "constraint_method", func(_ *http.Request, p map[string]interface{}) {
			p["constraints"] = map[string]interface{}{testIdentity: map[string]interface{}{"methods": []string{"POST"}, "paths": []string{"/insert/journald/upload"}}}
		}},
		{"path", "constraint_path", func(_ *http.Request, p map[string]interface{}) {
			p["constraints"] = map[string]interface{}{testIdentity: map[string]interface{}{"methods": []string{"GET"}, "paths": []string{"/insert/journald/upload"}}}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, req := validConfig(), validRequest()
			req.Header.Set("X-Mtls-Identity", testIdentity)
			req.Header.Set("X-Forwarded-Tls-Client-Cert", testIdentity)
			tc.change(req, (*cfg)["policy"].(map[string]interface{}))
			reached := false
			m := newTestMiddleware(t, cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached = true; w.WriteHeader(200) }))
			w := httptest.NewRecorder()
			m.ServeHTTP(w, req)
			if tc.reason == "" {
				if w.Code != 200 || !reached {
					t.Fatalf("status=%d reached=%v", w.Code, reached)
				}
				return
			}
			if w.Code != 403 || reached || w.Header().Get("X-Mtls-Authz-Reason") != tc.reason || w.Body.String() != "forbidden\n" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d reached=%v headers=%v body=%q", w.Code, reached, w.Header(), w.Body.String())
			}
		})
	}
}

func TestChainValiditySkew(t *testing.T) {
	for index, name := range []string{"leaf", "intermediate", "anchor"} {
		for _, edge := range []struct {
			name          string
			before, after time.Duration
			allow         bool
		}{
			{"expired", -time.Hour, -60*time.Second - time.Nanosecond, false},
			{"expiry-edge", -time.Hour, -60 * time.Second, true},
			{"future", 60*time.Second + time.Nanosecond, time.Hour, false},
			{"future-edge", 60 * time.Second, time.Hour, true},
		} {
			t.Run(name+"/"+edge.name, func(t *testing.T) {
				r := validRequest()
				c := r.TLS.VerifiedChains[0][index]
				c.NotBefore = testNow.Add(edge.before)
				c.NotAfter = testNow.Add(edge.after)
				w := httptest.NewRecorder()
				newTestMiddleware(t, validConfig(), nil).ServeHTTP(w, r)
				if (w.Code == 200) != edge.allow {
					t.Fatalf("status=%d", w.Code)
				}
				if !edge.allow && w.Header().Get("X-Mtls-Authz-Reason") != "cert_time" {
					t.Fatal(w.Header())
				}
			})
		}
	}
}

func TestExactConstraintPath(t *testing.T) {
	for _, path := range []string{"/insert/journald/upload", "/insert/journald/upload/", "/insert/journald/upload/extra", "/INSERT/journald/upload"} {
		t.Run(path, func(t *testing.T) {
			cfg := validConfig()
			(*cfg)["policy"].(map[string]interface{})["constraints"] = map[string]interface{}{testIdentity: map[string]interface{}{"methods": []string{"POST"}, "paths": []string{"/insert/journald/upload"}}}
			r := validRequest()
			r.Method = "POST"
			r.URL.Path = path
			w := httptest.NewRecorder()
			newTestMiddleware(t, cfg, nil).ServeHTTP(w, r)
			if (w.Code == 200) != (path == "/insert/journald/upload") {
				t.Fatal(w.Code)
			}
		})
	}
}

type capableWriter struct{ *httptest.ResponseRecorder }

func (*capableWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) { return nil, nil, nil }

type unreadableBody struct{}

func (unreadableBody) Read([]byte) (int, error) { panic("body read by authorization") }
func (unreadableBody) Close() error             { return nil }

func TestHeadersAndResponseWriter(t *testing.T) {
	for _, forward := range []string{"", "X-Mtls-Identity", "x-mtls-custom-identity"} {
		t.Run(forward, func(t *testing.T) {
			cfg := validConfig()
			(*cfg)["policy"].(map[string]interface{})["forwardIdentityHeader"] = forward
			w := &capableWriter{httptest.NewRecorder()}
			m := newTestMiddleware(t, cfg, http.HandlerFunc(func(got http.ResponseWriter, r *http.Request) {
				if got != w {
					t.Fatal("response writer replaced")
				}
				if _, ok := got.(http.Hijacker); !ok {
					t.Fatal("hijacker lost")
				}
				if _, ok := got.(http.Flusher); !ok {
					t.Fatal("flusher lost")
				}
				for key, values := range r.Header {
					lower := strings.ToLower(key)
					if strings.EqualFold(key, forward) {
						if len(values) != 1 || values[0] != testIdentity {
							t.Fatal(values)
						}
						continue
					}
					if strings.HasPrefix(lower, "x-mtls-") || strings.HasPrefix(lower, "x-forwarded-tls-client-cert") {
						t.Fatal("forged header survived", key)
					}
				}
				if forward != "" && r.Header.Get(forward) != testIdentity {
					t.Fatal("missing identity")
				}
				if r.Header.Get("X-Keep") != "kept" {
					t.Fatal("unrelated header removed")
				}
			}))
			r := validRequest()
			r.Body = unreadableBody{}
			r.Header = http.Header{"x-mTLS-Forged": []string{"forged"}, "X-Mtls-Identity": []string{"forged"}, "x-forwarded-tls-client-cert": []string{"forged"}, "X-Forwarded-Tls-Client-Cert-Info": []string{"forged"}, "X-Keep": []string{"kept"}}
			if forward != "" {
				r.Header[strings.ToLower(forward)] = []string{"spoofed"}
			}
			m.ServeHTTP(w, r)
		})
	}
}

func TestNewRejectsMalformedPolicy(t *testing.T) {
	cases := map[string]string{
		"unknown": "{\"unknown\":1}", "wrong-version": "{\"schemaVersion\":2}", "weak-int": "{\"schemaVersion\":\"1\"}", "weak-bool": "{\"stripHeaders\":\"yes\"}", "false-strip": "{\"stripHeaders\":false}",
		"empty-app": "{\"app\":\"\"}", "empty-issuer": "{\"trustedIssuers\":[]}", "bad-issuer": "{\"trustedIssuers\":[\"ABC\"]}", "prefix-colon": "{\"identityPrefix\":\"urn:noqer:mtls:clients\"}", "bad-prefix": "{\"identityPrefix\":\"urn:other:\"}",
		"null-app": "{\"app\":null}", "null-identity": "{\"identities\":[null]}", "null-list": "{\"identities\":null}", "string-list": "{\"identities\":\"urn:noqer:mtls:clients:alice\"}", "case-key": "{\"App\":\"oops\"}",
		"bad-identity": "{\"identities\":[\"urn:noqer:mtls:clients:Alice\"]}", "outside-prefix": "{\"disabledIdentities\":[\"urn:noqer:mtls:other:alice\"]}",
		"null-constraint": "{\"constraints\":{\"urn:noqer:mtls:clients:alice\":null}}", "unknown-constraint": "{\"constraints\":{\"urn:noqer:mtls:clients:alice\":{\"method\":[\"GET\"]}}}",
		"bad-block": "{\"blockedFingerprints\":[{\"fingerprint\":\"x\"}]}", "null-block": "{\"blockedFingerprints\":[null]}", "bad-header": "{\"forwardIdentityHeader\":\"X-Foo\\r\\nX-Bad\"}",
	}
	for name, patch := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := validConfig()
			var updates map[string]interface{}
			if err := json.Unmarshal([]byte(patch), &updates); err != nil {
				t.Fatal(err)
			}
			for k, v := range updates {
				(*cfg)["policy"].(map[string]interface{})[k] = v
			}
			if h, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil || h != nil {
				t.Fatal("accepted malformed policy")
			}
		})
	}
	for _, key := range []string{"trustedIssuers", "identities", "disabledIdentities"} {
		t.Run("duplicate/"+key, func(t *testing.T) {
			cfg := validConfig()
			p := (*cfg)["policy"].(map[string]interface{})
			value := testIdentity
			if key == "trustedIssuers" {
				value = strings.Repeat("a", 64)
			}
			p[key] = []string{value, value}
			if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
				t.Fatal("accepted duplicate")
			}
		})
	}
	for _, raw := range []interface{}{nil, "policy", []interface{}{map[string]interface{}{"schemaVersion": 1}}, map[string]string{"app": "test"}} {
		cfg := map[string]interface{}{"policy": raw}
		if _, err := New(context.Background(), http.NotFoundHandler(), &cfg, "test"); err == nil {
			t.Fatalf("accepted %T", raw)
		}
	}
	for _, cfg := range []*map[string]interface{}{nil, CreateConfig(), &map[string]interface{}{"other": true}, &map[string]interface{}{"policy": map[string]interface{}{}, "constraints": map[string]interface{}{}}} {
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Fatal("accepted invalid outer block")
		}
	}
	if _, err := New(context.Background(), nil, validConfig(), "test"); err == nil {
		t.Fatal("accepted nil next")
	}
}

func TestConstraintValidation(t *testing.T) {
	for _, path := range []string{"relative", "/trailing/", "/double//slash", "/a/../b", "/x..y", "/x?y", "/x#y", "/encoded%2fpath", "/back\\slash", "/control\n", "/ümlaut"} {
		t.Run(path, func(t *testing.T) {
			cfg := validConfig()
			(*cfg)["policy"].(map[string]interface{})["constraints"] = map[string]interface{}{testIdentity: map[string]interface{}{"methods": []string{"POST"}, "paths": []string{path}}}
			if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
				t.Fatal("accepted bad path")
			}
		})
	}
	for _, rule := range []constraint{{}, {Methods: []string{"POST"}}, {Paths: []string{"/"}}, {Methods: []string{"post"}, Paths: []string{"/"}}, {Methods: []string{"CUSTOM"}, Paths: []string{"/"}}, {Methods: []string{"GET", "GET"}, Paths: []string{"/"}}, {Methods: []string{"GET"}, Paths: []string{"/", "/"}}} {
		data, _ := json.Marshal(rule)
		var raw map[string]interface{}
		_ = json.Unmarshal(data, &raw)
		cfg := validConfig()
		(*cfg)["policy"].(map[string]interface{})["constraints"] = map[string]interface{}{testIdentity: raw}
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Fatal("accepted bad rule", rule)
		}
	}
}

func TestIdentitySyntax(t *testing.T) {
	for _, id := range []string{"urn:noqer:mtls:clients:a", "urn:noqer:mtls:clients:a-b", "urn:noqer:mtls:client-1:a--b"} {
		if !validIdentity(id, strings.Split(id, ":")[0]+":noqer:mtls:") {
			t.Fatal(id)
		}
	}
	for _, id := range []string{"urn:noqer:mtls:clients:-a", "urn:noqer:mtls:clients:a-", "urn:noqer:mtls:clients:a_b", "URN:noqer:mtls:clients:a", "urn:noqer:mtls:client--1:a", "urn:noqer:mtls:clients:a%62", "urn:noqer:mtls:clients:" + strings.Repeat("a", 128)} {
		if validIdentity(id, "urn:noqer:mtls:") {
			t.Fatal(id)
		}
	}
}

func TestSnapshotAndConcurrentRequests(t *testing.T) {
	cfg := validConfig()
	m := newTestMiddleware(t, cfg, nil)
	(*cfg)["policy"].(map[string]interface{})["identities"].([]string)[0] = "urn:noqer:mtls:clients:bob"
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			m.ServeHTTP(w, validRequest())
			if w.Code != 200 {
				t.Errorf("status=%d", w.Code)
			}
		}()
	}
	wg.Wait()
}

func TestLogs(t *testing.T) {
	// This test is serial: the plugin logger is shared across middleware instances.
	saved := decisionLogger.Writer()
	var buffer strings.Builder
	decisionLogger.SetOutput(&buffer)
	defer func() { decisionLogger.SetOutput(saved) }()
	m := newTestMiddleware(t, validConfig(), nil)
	r := validRequest()
	r.Host = "host\nforged=line"
	r.URL.Path = "/path\nforged=line"
	r.URL.RawQuery = "secret=never-log"
	m.identities = map[string]bool{}
	m.ServeHTTP(httptest.NewRecorder(), r)
	log := buffer.String()
	if strings.Count(log, "\n") != 2 || !strings.Contains(log, "event=deny reason=not_enrolled") || !strings.Contains(log, "leafFp=\""+fingerprint([]byte("leaf"))[:16]+"\"") || strings.Contains(log, "secret=") || strings.Contains(log, fingerprint([]byte("leaf"))) {
		t.Fatal(log)
	}
}

func TestPolicyJSON(t *testing.T) {
	data, err := json.Marshal((*validConfig())["policy"])
	if err != nil {
		t.Fatal(err)
	}
	good := string(data)
	cfg := map[string]interface{}{"policyJSON": good}
	newTestMiddleware(t, &cfg, nil)
	for _, bad := range []interface{}{nil, 1, map[string]interface{}{}, "", "null", "[]", "\"string\"", "{}", good + "{}", good + " trailing", strings.Replace(good, `"schemaVersion":1`, `"schemaVersion":"1"`, 1), strings.Replace(good, `"app":"test"`, `"app":"test","app":"other"`, 1), strings.Replace(good, `"app":"test"`, `"app":null`, 1), `{"schemaVersion":1,"constraints":{"x":{"methods":["GET"],"methods":["POST"]}}}`, `{"x":[` + strings.Repeat("[", 34) + "1" + strings.Repeat("]", 34) + "]}", `{"app":`, `{"app":]}`} {
		cfg := map[string]interface{}{"policyJSON": bad}
		if _, err := New(context.Background(), http.NotFoundHandler(), &cfg, "test"); err == nil {
			t.Fatalf("accepted bad JSON %#v", bad)
		}
	}
	cfg["policy"] = (*validConfig())["policy"]
	if _, err := New(context.Background(), http.NotFoundHandler(), &cfg, "test"); err == nil {
		t.Fatal("accepted both transports")
	}
}

func TestAdditionalPolicyValidation(t *testing.T) {
	for _, value := range []interface{}{
		[]objectForTest{{"fingerprint": strings.Repeat("a", 64)}, {"fingerprint": strings.Repeat("a", 64)}},
		[]objectForTest{{"fingerprint": strings.Repeat("a", 64), "expires": "2026-02-30"}},
		[]objectForTest{{"fingerprint": strings.Repeat("a", 64), "extra": true}},
	} {
		cfg := validConfig()
		(*cfg)["policy"].(map[string]interface{})["blockedFingerprints"] = value
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Fatal("accepted invalid blocked fingerprint")
		}
	}
	cfg := validConfig()
	(*cfg)["policy"].(map[string]interface{})["constraints"] = map[string]interface{}{"urn:noqer:mtls:other:alice": map[string]interface{}{"methods": []string{"GET"}, "paths": []string{"/"}}}
	if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
		t.Fatal("accepted outside constraint identity")
	}
}

type objectForTest = map[string]interface{}

func TestNamespaceAndForwardHeaderValidation(t *testing.T) {
	for _, prefix := range []string{"", "urn:", "urn:noqer:mtls:", "urn:noqer:mtls:clients", "urn:noqer:mtls:Clients:", "urn:noqer:mtls:clients:alice:"} {
		cfg := validConfig()
		p := (*cfg)["policy"].(map[string]interface{})
		p["identityPrefix"] = prefix
		p["identities"] = []string{}
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Fatalf("accepted broad/invalid prefix %q", prefix)
		}
	}
	for _, header := range []string{"Host", "Authorization", "Cookie", "Connection", "X-Forwarded-For", "X-Custom-Identity", "X-Mtls-", "X-Mtls-Bad Name"} {
		cfg := validConfig()
		(*cfg)["policy"].(map[string]interface{})["forwardIdentityHeader"] = header
		if _, err := New(context.Background(), http.NotFoundHandler(), cfg, "test"); err == nil {
			t.Fatalf("accepted unsafe identity header %q", header)
		}
	}
}

func testSAN(identity string) pkix.Extension {
	data, err := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, Bytes: []byte(identity)}})
	if err != nil {
		panic(err)
	}
	return pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: data}
}

func TestCertificateIdentityBytes(t *testing.T) {
	for _, raw := range []string{testIdentity, "URN:noqer:mtls:clients:alice", "UrN:noqer:mtls:clients:alice"} {
		t.Run(raw, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			tpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour), ExtraExtensions: []pkix.Extension{testSAN(raw)}}
			der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			// Demonstrate why authorizing the parsed URL string alone is insufficient.
			if leaf.URIs[0].String() != testIdentity {
				t.Fatal("fixture must normalize to the enrolled URI", leaf.URIs[0])
			}
			req := validRequest()
			req.TLS.PeerCertificates[0] = leaf
			req.TLS.VerifiedChains[0][0] = leaf
			w := httptest.NewRecorder()
			newTestMiddleware(t, validConfig(), nil).ServeHTTP(w, req)
			if raw == testIdentity {
				if w.Code != 200 {
					t.Fatal(w.Code)
				}
			} else if w.Code != 403 || w.Header().Get("X-Mtls-Authz-Reason") != "identity_invalid" {
				t.Fatal("raw SAN bytes were normalized", w.Code, w.Header())
			}
		})
	}
}

func TestMalformedRawSAN(t *testing.T) {
	canonical := testSAN(testIdentity)
	compound, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 6, IsCompound: true, Bytes: []byte{0x05, 0x00}}})
	wrongClass, _ := asn1.Marshal([]asn1.RawValue{{Class: 0, Tag: 6, Bytes: []byte(testIdentity)}})
	for _, exts := range [][]pkix.Extension{nil, {canonical, canonical}, {{Id: canonical.Id, Value: []byte{0x30, 0x81}}}, {{Id: canonical.Id, Value: append(append([]byte{}, canonical.Value...), 0)}}, {{Id: canonical.Id, Value: compound}}, {{Id: canonical.Id, Value: wrongClass}}, {{Id: canonical.Id, Value: []byte{0x30, 0x00}}}, {{Id: canonical.Id, Value: []byte{0x04, 0x00}}}} {
		req := validRequest()
		req.TLS.PeerCertificates[0].Extensions = exts
		w := httptest.NewRecorder()
		newTestMiddleware(t, validConfig(), nil).ServeHTTP(w, req)
		if w.Code != 403 || w.Header().Get("X-Mtls-Authz-Reason") != "identity_invalid" {
			t.Fatal("malformed or missing raw SAN accepted", w.Code)
		}
	}
}

func TestConstraintRejectsEncodedAliases(t *testing.T) {
	cfg := validConfig()
	(*cfg)["policy"].(map[string]interface{})["constraints"] = map[string]interface{}{testIdentity: map[string]interface{}{"methods": []string{"POST"}, "paths": []string{"/insert/journald/upload"}}}
	m := newTestMiddleware(t, cfg, nil)
	for _, path := range []string{"/insert%2Fjournald/upload", "/insert%2fjournald/upload", "/insert/journald/%75pload"} {
		req := validRequest()
		req.Method = "POST"
		req.URL, _ = url.Parse("https://app.test" + path)
		if req.URL.Path != "/insert/journald/upload" {
			t.Fatal("fixture must decode to the allowed path")
		}
		w := httptest.NewRecorder()
		m.ServeHTTP(w, req)
		if w.Code != 403 || w.Header().Get("X-Mtls-Authz-Reason") != "constraint_path" {
			t.Fatal("encoded alias accepted", path, w.Code)
		}
	}
}

func TestIgnoredOrUnknownRawSANs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		extra  asn1.RawValue
		reason string
	}{
		{"registeredID", asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{0x2a, 0x03}}, "identity_ambiguous"},
		{"otherName", asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x30, 0x00}}, "identity_ambiguous"},
		{"directoryName", asn1.RawValue{Class: 2, Tag: 4, IsCompound: true, Bytes: []byte{0x30, 0x00}}, "identity_ambiguous"},
		{"secondURI", asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(testIdentity)}, "identity_ambiguous"},
		{"unknownTag", asn1.RawValue{Class: 2, Tag: 9, Bytes: []byte{1}}, "identity_invalid"},
	} {
		// Check both orderings so a URI cannot hide an unsupported SAN before/after it.
		for _, first := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/extra-first=%v", tc.name, first), func(t *testing.T) {
				uri := asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(testIdentity)}
				names := []asn1.RawValue{uri, tc.extra}
				if first {
					names = []asn1.RawValue{tc.extra, uri}
				}
				data, err := asn1.Marshal(names)
				if err != nil {
					t.Fatal(err)
				}
				req := validRequest()
				req.TLS.PeerCertificates[0].Extensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: data}}
				w := httptest.NewRecorder()
				newTestMiddleware(t, validConfig(), nil).ServeHTTP(w, req)
				if w.Code != 403 || w.Header().Get("X-Mtls-Authz-Reason") != tc.reason {
					t.Fatalf("extra SAN accepted or misclassified: status=%d reason=%s", w.Code, w.Header().Get("X-Mtls-Authz-Reason"))
				}
			})
		}
	}
}

func TestConstraintKeyMustBeEnrolled(t *testing.T) {
	for _, id := range []string{"urn:noqer:mtls:clients:alicee", "urn:noqer:mtls:clients:disabled"} {
		cfg := validConfig()
		p := (*cfg)["policy"].(map[string]interface{})
		p["disabledIdentities"] = []string{"urn:noqer:mtls:clients:disabled"}
		p["constraints"] = map[string]interface{}{id: map[string]interface{}{"methods": []string{"POST"}, "paths": []string{"/upload"}}}
		handler, err := New(context.Background(), http.NotFoundHandler(), cfg, "test")
		if err == nil || handler != nil || !strings.Contains(err.Error(), "enrolled identity") {
			t.Fatalf("unused constraint must fail loading: handler=%v error=%v", handler, err)
		}
	}
}

func TestIdentityLogIsBounded(t *testing.T) {
	saved := decisionLogger.Writer()
	var buffer strings.Builder
	decisionLogger.SetOutput(&buffer)
	defer decisionLogger.SetOutput(saved)
	m := newTestMiddleware(t, validConfig(), nil)
	identity := "urn:noqer:mtls:clients:" + strings.Repeat("a", 20*1024)
	req := validRequest()
	leaf := req.TLS.PeerCertificates[0]
	leaf.URIs[0], _ = url.Parse(identity)
	leaf.Extensions = []pkix.Extension{testSAN(identity)}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != 403 || w.Header().Get("X-Mtls-Authz-Reason") != "identity_invalid" {
		t.Fatal("overlong identity accepted")
	}
	if buffer.Len() > 2048 || !strings.Contains(buffer.String(), `identity="`+identity[:128]+`[truncated]"`) {
		t.Fatal("identity log was not bounded", buffer.Len())
	}
}
