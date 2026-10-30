//go:build integration

package integration_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const module = "github.com/zekihan/traefik-mtls-authz"
const alice = "urn:noqer:mtls:clients:alice"
const bob = "urn:noqer:mtls:clients:bob"

type object = map[string]interface{}

type certificate struct {
	parsed *x509.Certificate
	key    *ecdsa.PrivateKey
	der    []byte
	pair   tls.Certificate
}

func issue(t *testing.T, parent *certificate, name string, ca bool, uris []string, dns []string, notAfter time.Time, extraNames ...asn1.RawValue) *certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter, IsCA: ca, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dns}
	if ca {
		tpl.KeyUsage |= x509.KeyUsageCertSign
		tpl.MaxPathLen = 2
	} else {
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	for _, s := range uris {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		tpl.URIs = append(tpl.URIs, u)
	}
	// Build the SAN by hand so tests preserve the CA-issued bytes, including
	// uppercase URI schemes that net/url normalizes in parsed certificate fields.
	if len(uris) > 0 {
		names := []asn1.RawValue{}
		for _, dnsName := range dns {
			names = append(names, asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte(dnsName)})
		}
		for _, uri := range uris {
			names = append(names, asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(uri)})
		}
		san, err := asn1.Marshal(append(names, extraNames...))
		if err != nil {
			t.Fatal(err)
		}
		tpl.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: san}}
	}
	issuer, signer := tpl, key
	if parent != nil {
		issuer, signer = parent.parsed, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{der}
	if parent != nil {
		chain = append(chain, parent.pair.Certificate...)
	}
	return &certificate{parsed: parsed, key: key, der: der, pair: tls.Certificate{Certificate: chain, PrivateKey: key, Leaf: parsed}}
}
func fp(c *certificate) string { sum := sha256.Sum256(c.der); return hex.EncodeToString(sum[:]) }
func writePEM(t *testing.T, path, kind string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: data}), 0600); err != nil {
		t.Fatal(err)
	}
}
func writeJSON(t *testing.T, path string, value interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}
func port(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

type fixture struct {
	t                                   *testing.T
	dir, project, address, proxyAddress string
	source                              string
	root, intermediate                  *certificate
	clients                             map[string]*certificate
	pool                                *x509.CertPool
	config                              object
	catchall                            bool
	streamStarted                       chan struct{}
	streamOnce                          sync.Once
	eventRelease                        chan struct{}
}

func newFixture(t *testing.T, catchall, strict, tickets bool) *fixture {
	return fixtureWithLogLevel(t, catchall, strict, tickets, "INFO")
}

func fixtureWithLogLevel(t *testing.T, catchall, strict, tickets bool, logLevel string) *fixture {
	return fixtureWithLogConfig(t, catchall, strict, tickets, object{"level": logLevel, "noColor": true})
}

func fixtureWithLogConfig(t *testing.T, catchall, strict, tickets bool, logConfig object) *fixture {
	t.Helper()
	f := &fixture{t: t, dir: t.TempDir(), project: fmt.Sprintf("mtls-%d-%d", os.Getpid(), time.Now().UnixNano()), address: port(t), proxyAddress: port(t), clients: make(map[string]*certificate), catchall: catchall, streamStarted: make(chan struct{}), eventRelease: make(chan struct{})}
	expiry := time.Now().Add(time.Hour)
	f.root = issue(t, nil, "test-root", true, nil, nil, expiry)
	f.intermediate = issue(t, f.root, "test-intermediate", true, nil, nil, expiry)
	f.clients["alice"] = issue(t, f.intermediate, "alice", false, []string{alice}, nil, expiry)
	f.clients["bob"] = issue(t, f.intermediate, "bob", false, []string{bob}, nil, expiry)
	f.clients["unenrolled"] = issue(t, f.intermediate, "unenrolled", false, []string{"urn:noqer:mtls:clients:unknown"}, nil, expiry)
	f.clients["ambiguous"] = issue(t, f.intermediate, "two-uris", false, []string{alice, bob}, nil, expiry)
	f.clients["dns"] = issue(t, f.intermediate, "extra-san", false, []string{alice}, []string{"extra.test"}, expiry)
	f.clients["missing"] = issue(t, f.intermediate, "no-uri", false, nil, nil, expiry)
	f.clients["invalid"] = issue(t, f.intermediate, "invalid-uri", false, []string{"urn:noqer:mtls:clients:Alice"}, nil, expiry)
	f.clients["uppercase"] = issue(t, f.intermediate, "uppercase-uri-scheme", false, []string{"URN:noqer:mtls:clients:alice"}, nil, expiry)
	if f.clients["uppercase"].parsed.URIs[0].String() != alice {
		t.Fatal("uppercase SAN fixture must normalize to alice")
	}
	// Native x509 parsing ignores these entries; the plugin must inspect raw SANs.
	f.clients["registered-id"] = issue(t, f.intermediate, "uri-plus-registered-id", false, []string{alice}, nil, expiry, asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{0x2a, 0x03}}) // OID 1.2.3
	f.clients["unknown-san"] = issue(t, f.intermediate, "uri-plus-unknown-general-name", false, []string{alice}, nil, expiry, asn1.RawValue{Class: 2, Tag: 9, Bytes: []byte{1}})
	f.clients["disabled"] = issue(t, f.intermediate, "disabled", false, []string{"urn:noqer:mtls:clients:disabled"}, nil, expiry)
	f.clients["blocked"] = issue(t, f.intermediate, "blocked", false, []string{alice}, nil, expiry)
	f.clients["expired"] = issue(t, f.intermediate, "expired", false, []string{alice}, nil, time.Now().Add(-time.Minute))
	other := issue(t, nil, "other-root", true, nil, nil, expiry)
	f.clients["wrong-ca"] = issue(t, other, "wrong-ca", false, []string{alice}, nil, expiry)
	server := issue(t, f.root, "server", false, nil, []string{"*.test"}, expiry)
	f.pool = x509.NewCertPool()
	f.pool.AddCert(f.root.parsed)
	writePEM(t, filepath.Join(f.dir, "root.pem"), "CERTIFICATE", f.root.der)
	writePEM(t, filepath.Join(f.dir, "server.pem"), "CERTIFICATE", server.der)
	key, err := x509.MarshalECPrivateKey(server.key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(f.dir, "server-key.pem"), "EC PRIVATE KEY", key)
	if err := os.Mkdir(filepath.Join(f.dir, "dynamic"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(f.dir, "logs"), 0700); err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(f.backend))
	t.Cleanup(backend.Close)
	policyA := f.policy("app-a", []string{alice})
	policyA["forwardIdentityHeader"] = "X-Mtls-Identity"
	middlewares := object{
		"a":           object{"plugin": object{"traefik-mtls-authz": object{"policy": policyA}}},
		"a2":          object{"plugin": object{"traefik-mtls-authz": object{"policy": f.policy("app-a2", []string{bob})}}},
		"b":           object{"plugin": object{"traefik-mtls-authz": object{"policy": f.policy("app-b", []string{bob})}}},
		"broken":      object{"plugin": object{"traefik-mtls-authz": object{"policy": object{"schemaVersion": "1"}}}},
		"constrained": object{"plugin": object{"traefik-mtls-authz": object{"policy": f.policy("constrained", []string{alice})}}},
	}
	cp := middlewares["constrained"].(object)["plugin"].(object)["traefik-mtls-authz"].(object)["policy"].(object)
	cp["constraints"] = object{alice: object{"methods": []string{"POST"}, "paths": []string{"/insert/journald/upload"}}}
	routers := object{}
	add := func(name, host, option, middleware string, priority int) {
		rule := "Host(`" + host + "`)"
		if host == "" {
			rule = "PathPrefix(`/`)"
		}
		r := object{"rule": rule, "priority": priority, "entryPoints": []string{"web", "proxy"}, "service": "backend", "tls": object{"options": option}}
		if middleware != "" {
			r["middlewares"] = []string{middleware}
		}
		routers[name] = r
	}
	add("app-a", "app-a.test", "mtls-a", "a", 100)
	add("app-a2", "app-a2.test", "mtls-a", "a2", 100)
	add("app-b", "app-b.test", "mtls-b", "b", 100)
	add("plain", "plain.test", "default", "", 100)
	add("broken", "broken.test", "mtls-a", "broken", 100)
	add("constrained", "constrained.test", "mtls-a", "constrained", 100)
	add("bypass-hi", "bypass.test", "mtls-a", "broken", 20)
	add("bypass-lo", "bypass.test", "mtls-a", "", 10)
	add("conflict-a", "conflict.test", "mtls-a", "a", 20)
	add("conflict-d", "conflict.test", "default", "", 10)
	add("catchall-mtls", "", "mtls-a", "", 1)
	if catchall {
		add("catchall", "", "default", "", 1)
	}
	option := func() object {
		return object{"minVersion": "VersionTLS12", "sniStrict": true, "disableSessionTickets": !tickets, "clientAuth": object{"caFiles": []string{"/fixture/root.pem"}, "clientAuthType": "RequireAndVerifyClientCert"}}
	}
	f.config = object{"http": object{"routers": routers, "middlewares": middlewares, "services": object{"backend": object{"loadBalancer": object{"servers": []object{{"url": backend.URL}}}}}}, "tls": object{"certificates": []object{{"certFile": "/fixture/server.pem", "keyFile": "/fixture/server-key.pem"}}, "options": object{"default": object{}, "mtls-a": option(), "mtls-b": option()}}}
	f.save()
	static := object{
		"global": object{"checkNewVersion": false, "sendAnonymousUsage": false},
		"core":   object{"strictTLSOptions": strict}, "log": logConfig,
		"entryPoints":  object{"web": object{"address": f.address}, "proxy": object{"address": f.proxyAddress, "proxyProtocol": object{"trustedIPs": []string{"127.0.0.1/32"}}}},
		"providers":    object{"providersThrottleDuration": "100ms", "file": object{"directory": "/fixture/dynamic", "watch": true}},
		"experimental": object{"abortOnPluginFailure": true, "localPlugins": object{"traefik-mtls-authz": object{"moduleName": module}}},
	}
	writeJSON(t, filepath.Join(f.dir, "static.json"), static)
	t.Cleanup(func() {
		data, _ := f.compose("logs", "--no-color")
		artifact := filepath.Join("artifacts", strings.ReplaceAll(t.Name(), "/", "-")+".log")
		_ = os.MkdirAll("artifacts", 0755)
		_ = os.WriteFile(artifact, data, 0600)
		if fileLog, err := os.ReadFile(filepath.Join(f.dir, "logs", "traefik.json")); err == nil {
			_ = os.WriteFile(artifact+".json", fileLog, 0600)
		}
		if t.Failed() {
			t.Logf("Traefik logs:\n%s", data)
		}
		if output, err := f.compose("down", "--timeout", "3"); err != nil {
			t.Logf("cleanup: %v: %s", err, output)
		}
	})
	if output, err := f.compose("up", "-d"); err != nil {
		t.Fatalf("compose up: %v\n%s", err, output)
	}
	f.await(func() bool {
		res, _, err := f.request("app-a.test", "app-a.test", "alice", tls.VersionTLS13, "GET", "/")
		return err == nil && res.StatusCode == 200
	})
	return f
}

func (f *fixture) policy(app string, identities []string) object {
	return object{"schemaVersion": 1, "app": app, "policyRevision": "integration-1", "trustedIssuers": []string{fp(f.root)}, "identityPrefix": "urn:noqer:mtls:clients:", "identities": identities, "disabledIdentities": []string{"urn:noqer:mtls:clients:disabled"}, "blockedFingerprints": []object{{"fingerprint": fp(f.clients["blocked"]), "expires": "2000-01-01"}}, "stripHeaders": true}
}
func (f *fixture) compose(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", append([]string{"compose", "-f", "compose.yaml", "-p", f.project}, args...)...)
	source := f.source
	if source == "" {
		var err error
		source, err = filepath.Abs("..")
		if err != nil {
			return nil, err
		}
	}
	cmd.Env = append(os.Environ(), "MTLS_SOURCE_DIR="+source, "MTLS_FIXTURE_DIR="+f.dir)
	return cmd.CombinedOutput()
}
func (f *fixture) await(ready func() bool) {
	f.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	f.t.Fatal("timed out waiting for Traefik state")
}
func (f *fixture) tlsConfig(sni, client string, version uint16) *tls.Config {
	cfg := &tls.Config{RootCAs: f.pool, ServerName: sni, MinVersion: version, MaxVersion: version}
	if client != "" {
		cfg.Certificates = []tls.Certificate{f.clients[client].pair}
	}
	return cfg
}
func (f *fixture) dial(sni, client string, version uint16, proxy bool) (*tls.Conn, error) {
	addr := f.address
	if proxy {
		addr = f.proxyAddress
	}
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if proxy {
		// PROXY v2, TCP over IPv4, 12-byte address block. Sent before ClientHello.
		header := append([]byte("\r\n\r\n\x00\r\nQUIT\n"), 0x21, 0x11, 0, 12, 192, 0, 2, 10, 127, 0, 0, 1, 0x30, 0x39, 0x01, 0xbb)
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, err
		}
	}
	secure := tls.Client(conn, f.tlsConfig(sni, client, version))
	if err := secure.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	return secure, nil
}
func exchange(conn net.Conn, host, method, path string, headers http.Header) (*http.Response, []byte, error) {
	req, err := http.NewRequest(method, "https://"+host+path, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header = headers
	if err := req.Write(conn); err != nil {
		return nil, nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	return response, body, err
}
func (f *fixture) request(sni, host, client string, version uint16, method, path string) (*http.Response, []byte, error) {
	conn, err := f.dial(sni, client, version, false)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()
	return exchange(conn, host, method, path, http.Header{"X-Mtls-Forged": []string{"spoof"}, "X-Mtls-Identity": []string{bob}, "X-Forwarded-Tls-Client-Cert": []string{"spoof"}, "X-Forwarded-Tls-Client-Cert-Info": []string{"spoof"}})
}
func (f *fixture) expect(sni, host, client string, version uint16, method, path string, status int, reason string) {
	f.t.Helper()
	res, body, err := f.request(sni, host, client, version, method, path)
	if err != nil {
		f.t.Fatal(err)
	}
	if res.StatusCode != status || res.Header.Get("X-Mtls-Authz-Reason") != reason {
		f.t.Fatalf("%s/%s %s: status=%d reason=%q body=%q; want %d %s", sni, host, client, res.StatusCode, res.Header.Get("X-Mtls-Authz-Reason"), body, status, reason)
	}
	if status == 403 && (res.Header.Get("Cache-Control") != "no-store" || string(body) != "forbidden\n") {
		f.t.Fatal("bad deny response", res.Header, string(body))
	}
	if status == 200 && path == "/" {
		switch host {
		case "app-a.test":
			f.assertBackendHeaders(body, alice)
		case "app-a2.test", "app-b.test":
			f.assertBackendHeaders(body, "")
		}
	}

}
func (f *fixture) assertBackendHeaders(body []byte, identity string) {
	f.t.Helper()
	var headers http.Header
	if err := json.Unmarshal(body, &headers); err != nil {
		f.t.Fatal(err)
	}
	if headers.Get("X-Mtls-Identity") != identity {
		f.t.Fatal("incorrect forwarded identity", headers)
	}
	for key := range headers {
		lower := strings.ToLower(key)
		if lower == "x-mtls-identity" && identity != "" {
			continue
		}
		if strings.HasPrefix(lower, "x-mtls-") || lower == "x-forwarded-tls-client-cert" || lower == "x-forwarded-tls-client-cert-info" {
			f.t.Fatal("forged header survived", key, headers)
		}
	}
}

func (f *fixture) save() { // File-provider parsing stringifies primitive map values. Use a serialized
	// envelope so strict JSON types survive the provider boundary.
	data, err := json.Marshal(f.config)
	if err != nil {
		f.t.Fatal(err)
	}
	var wire object
	if err := json.Unmarshal(data, &wire); err != nil {
		f.t.Fatal(err)
	}
	for _, entry := range wire["http"].(map[string]interface{})["middlewares"].(map[string]interface{}) {
		plugin := entry.(map[string]interface{})["plugin"].(map[string]interface{})["traefik-mtls-authz"].(map[string]interface{})
		if policy, ok := plugin["policy"]; ok {
			encoded, err := json.Marshal(policy)
			if err != nil {
				f.t.Fatal(err)
			}
			delete(plugin, "policy")
			plugin["policyJSON"] = string(encoded)
		}
	}
	writeJSON(f.t, filepath.Join(f.dir, "dynamic", "config.yaml"), wire)
}
func (f *fixture) plugin(name string) object {
	return f.config["http"].(object)["middlewares"].(object)[name].(object)["plugin"].(object)["traefik-mtls-authz"].(object)
}

func (f *fixture) backend(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ws":
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade needed", 400)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		sum := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", base64.StdEncoding.EncodeToString(sum[:]))
		if rw.Flush() != nil {
			return
		}
		for {
			var header [2]byte
			if _, err := io.ReadFull(rw, header[:]); err != nil {
				return
			}
			size := int(header[1] & 127)
			if size > 125 || header[1]&128 == 0 {
				return
			}
			var mask [4]byte
			if _, err := io.ReadFull(rw, mask[:]); err != nil {
				return
			}
			payload := make([]byte, size)
			if _, err := io.ReadFull(rw, payload); err != nil {
				return
			}
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
			if _, err := rw.Write(append([]byte{0x81, byte(size)}, payload...)); err != nil {
				return
			}
			if rw.Flush() != nil {
				return
			}
		}
	case "/stream":
		buf := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, buf); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		f.streamOnce.Do(func() { close(f.streamStarted) })
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fmt.Fprintf(w, "received=%d", n+5)
	case "/events":
		fmt.Fprint(w, "first\n")
		w.(http.Flusher).Flush()
		select {
		case <-f.eventRelease:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, "last\n")
	default:
		w.Header().Set("X-Test-Backend-URI", r.RequestURI)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(r.Header)
	}
}

func TestTraefikMatrix(t *testing.T) {
	for _, catchall := range []bool{false, true} {
		t.Run(fmt.Sprintf("catchall=%v", catchall), func(t *testing.T) {
			f := newFixture(t, catchall, true, false)
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				t.Run(fmt.Sprintf("TLS-%x", version), func(t *testing.T) {
					parent := f.t
					f.t = t
					defer func() { f.t = parent }()
					for _, client := range []string{"", "wrong-ca", "expired"} {
						if res, _, err := f.request("app-a.test", "app-a.test", client, version, "GET", "/"); err == nil {
							t.Fatalf("%s handshake unexpectedly accepted: %v", client, res)
						}
					}
					f.expect("app-a.test", "app-a.test", "alice", version, "GET", "/", 200, "")
					for client, reason := range map[string]string{"unenrolled": "not_enrolled", "ambiguous": "identity_ambiguous", "dns": "identity_ambiguous", "missing": "identity_missing", "invalid": "identity_invalid", "uppercase": "identity_invalid", "registered-id": "identity_ambiguous", "unknown-san": "identity_invalid", "blocked": "fingerprint_blocked", "disabled": "identity_disabled"} {
						f.expect("app-a.test", "app-a.test", client, version, "GET", "/", 403, reason)
					}
					f.expect("app-a.test", "app-b.test", "alice", version, "GET", "/", 421, "")
					f.expect("app-a.test", "plain.test", "alice", version, "GET", "/", 421, "")
					f.expect("app-a.test", "app-a2.test", "alice", version, "GET", "/", 403, "not_enrolled")
					f.expect("app-a.test", "app-a2.test", "bob", version, "GET", "/", 200, "")
					f.expect("app-b.test", "app-b.test", "bob", version, "GET", "/", 200, "")
					f.expect("constrained.test", "constrained.test", "alice", version, "POST", "/insert/journald/upload", 200, "")
					f.expect("constrained.test", "constrained.test", "alice", version, "GET", "/insert/journald/upload", 403, "constraint_method")
					// The stock entrypoint allows encoded slashes; enforce exact spelling in
					// the constrained authorization policy regardless of that default.
					for _, path := range []string{"/insert%2Fjournald/upload", "/insert%2fjournald/upload"} {
						f.expect("constrained.test", "constrained.test", "alice", version, "POST", path, 403, "constraint_path")
					}
					// Traefik normalizes unreserved encodings and dot segments before
					// middleware. The backend must receive exactly the same canonical path.
					for _, path := range []string{"/insert/journald/%75pload", "/insert/journald/./upload", "/insert/journald/discard/../upload"} {
						res, _, err := f.request("constrained.test", "constrained.test", "alice", version, "POST", path)
						if err != nil {
							t.Fatal(err)
						}
						if res.StatusCode != 200 || res.Header.Get("X-Test-Backend-URI") != "/insert/journald/upload" {
							t.Fatalf("normalization of %q: status=%d backend URI=%q", path, res.StatusCode, res.Header.Get("X-Test-Backend-URI"))
						}
					}
					for _, path := range []string{"/insert/journald/upload/", "/insert/journald/upload/extra"} {
						f.expect("constrained.test", "constrained.test", "alice", version, "POST", path, 403, "constraint_path")
					}
				})
			}
			for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
				if _, _, err := f.request("broken.test", "broken.test", "", version, "GET", "/"); err == nil {
					t.Fatal("failed middleware must still require a client certificate at TLS")
				}
			}
			fallback := 404
			if catchall {
				fallback = 421
			}
			for _, tc := range []struct {
				block     object
				wantError string
			}{
				{object{"policy": object{"schemaVersion": "1"}}, "cannot unmarshal string"},
				{object{"policy": f.policy("broken", []string{alice}), "constraints": object{}}, "exactly one key"},
				{object{"policy": []object{f.policy("broken", []string{alice})}}, "policy must be a JSON object"},
				{object{"policy": "bad"}, "policy must be a JSON object"},
				{object{"policy": nil}, "policy must be a JSON object"},
				{object{"policy": func() object { p := f.policy("broken", []string{alice}); p["unknown"] = true; return p }()}, "unknown field"},
				{object{"policy": func() object { p := f.policy("broken", []string{}); p["identityPrefix"] = "urn:noqer:mtls:"; return p }()}, "identityPrefix must be a full"},
				{object{"policy": func() object {
					p := f.policy("broken", []string{alice})
					p["forwardIdentityHeader"] = "Authorization"
					return p
				}()}, "forwardIdentityHeader must be a valid"},
			} {
				broken := tc.block
				f.config["http"].(object)["middlewares"].(object)["broken"] = object{"plugin": object{"traefik-mtls-authz": object{"policy": f.policy("broken", []string{alice})}}}
				f.save()
				f.await(func() bool {
					res, _, err := f.request("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/")
					return err == nil && res.StatusCode == 200
				})
				f.config["http"].(object)["middlewares"].(object)["broken"] = object{"plugin": object{"traefik-mtls-authz": broken}}
				f.save()
				// A valid router was active immediately before this reload; assert it disappears.
				encoded, _ := json.Marshal(broken)
				t.Logf("A1 rejecting policy %s", encoded)
				f.await(func() bool {
					res, _, err := f.request("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/")
					return err == nil && res.StatusCode == fallback
				})
				f.expect("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/", fallback, "")
				logs, err := f.compose("logs", "--no-color")
				if err != nil {
					t.Fatal(err)
				}
				latestFailure := ""
				for _, line := range strings.Split(string(logs), "\n") {
					if strings.Contains(line, "event=load reason=config_invalid") && strings.Contains(line, `router="broken@file"`) {
						latestFailure = line
					}
				}
				if !strings.Contains(latestFailure, tc.wantError) {
					t.Fatalf("wrong rejection cause; want %q in %s", tc.wantError, latestFailure)
				}
			}

			// Regression for R13: even native numeric/bool YAML scalars have already
			// become strings at the file-provider boundary. Never weaken validation.
			for _, raw := range []object{
				{"policy": f.policy("raw-native", []string{alice})},
				{"policy": f.policy("raw-native", []string{alice}), "unknown": true},
				{"policy": []object{f.policy("raw-list", []string{alice})}},
				{"policyJSON": `{"schemaVersion":1,"schemaVersion":1}`},
				{"policyJSON": `{} {}`},
			} {
				f.config["http"].(object)["middlewares"].(object)["broken"] = object{"plugin": object{"traefik-mtls-authz": object{"policy": f.policy("broken", []string{alice})}}}
				f.save()
				f.await(func() bool {
					res, _, err := f.request("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/")
					return err == nil && res.StatusCode == 200
				})
				path := filepath.Join(f.dir, "dynamic", "config.yaml")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var wire object
				if err := json.Unmarshal(data, &wire); err != nil {
					t.Fatal(err)
				}
				wire["http"].(map[string]interface{})["middlewares"].(map[string]interface{})["broken"] = object{"plugin": object{"traefik-mtls-authz": raw}}
				writeJSON(t, path, wire)
				f.await(func() bool {
					res, _, err := f.request("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/")
					return err == nil && res.StatusCode == fallback
				})
			}
			// Pin enforcement is checked after successful native TLS validation.
			f.plugin("a")["policy"].(object)["trustedIssuers"] = []string{strings.Repeat("a", 64)}
			f.save()
			f.await(func() bool {
				res, _, err := f.request("app-a.test", "app-a.test", "alice", tls.VersionTLS13, "GET", "/")
				return err == nil && res.Header.Get("X-Mtls-Authz-Reason") == "issuer_not_trusted"
			})
			f.plugin("a")["policy"].(object)["trustedIssuers"] = []string{fp(f.root)}
			f.save()
			f.await(func() bool {
				res, _, err := f.request("app-a.test", "app-a.test", "alice", tls.VersionTLS13, "GET", "/")
				return err == nil && res.StatusCode == 200
			})
			delete(f.config["http"].(object)["middlewares"].(object), "broken")
			f.save()
			f.await(func() bool {
				data, _ := f.compose("logs", "--no-color")
				return bytes.Contains(data, []byte("does not exist")) && bytes.Contains(data, []byte("broken@file"))
			})
			f.expect("broken.test", "broken.test", "alice", tls.VersionTLS13, "GET", "/", fallback, "")
			f.expect("bypass.test", "bypass.test", "unenrolled", tls.VersionTLS13, "GET", "/", 200, "")
			askedForCert := false
			cfg := f.tlsConfig("conflict.test", "", tls.VersionTLS13)
			cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				askedForCert = true
				return &tls.Certificate{}, nil
			}
			connForConflict, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", f.address, cfg)
			if err != nil {
				t.Fatal(err)
			}
			connForConflict.Close()
			if askedForCert {
				t.Fatal("strict conflict must use default TLS without requesting a certificate")
			}
			conflictStatus := 404
			if catchall {
				conflictStatus = 200
			}
			f.expect("conflict.test", "conflict.test", "", tls.VersionTLS13, "GET", "/", conflictStatus, "")
			unknownStatus := 404
			if catchall {
				unknownStatus = 200
			}
			f.expect("unknown.test", "unknown.test", "", tls.VersionTLS13, "GET", "/", unknownStatus, "")
			data, err := f.compose("logs", "--no-color")
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range []string{"event=deny reason=not_enrolled", "served by multiple routers with different TLS options", "catchall-mtls", "with no domains in its rule"} {
				if !bytes.Contains(data, []byte(line)) {
					t.Fatalf("missing log %q in %s", line, data)
				}
			}
			denyFormatted, loadFormatted := false, false
			for _, line := range bytes.Split(data, []byte("\n")) {
				if bytes.Contains(line, []byte("ERR ")) && bytes.Contains(line, []byte("plugin=plugin-traefik-mtls-authz")) {
					if bytes.Contains(line, []byte("event=deny reason=not_enrolled")) {
						denyFormatted = true
					}
					if bytes.Contains(line, []byte("event=load reason=config_invalid")) {
						loadFormatted = true
					}
				}
			}
			if !denyFormatted || !loadFormatted {
				t.Fatal("deny/load lines must pass through Traefik's ERROR logger")
			}
			if bytes.Contains(data, []byte("event=allow")) {
				t.Fatal("allow logs must be DEBUG, invisible at INFO")
			}
			conn, err := f.dial("app-a.test", "alice", tls.VersionTLS13, true)
			if err != nil {
				t.Fatal(err)
			}
			res, _, err := exchange(conn, "app-a.test", "GET", "/", nil)
			conn.Close()
			if err != nil || res.StatusCode != 200 {
				t.Fatalf("A5 PROXY v2 status=%v error=%v", res, err)
			}
			f.testSessions(false)
		})
	}
}

func (f *fixture) testSessions(enabled bool) {
	f.t.Helper()
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, client := range []string{"alice", "unenrolled"} {
			cfg := f.tlsConfig("app-a.test", client, version)
			cfg.ClientSessionCache = tls.NewLRUClientSessionCache(4)
			for attempt := 0; attempt < 2; attempt++ {
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				conn, err := tls.DialWithDialer(dialer, "tcp", f.address, cfg)
				if err != nil {
					f.t.Fatal(err)
				}
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				res, _, err := exchange(conn, "app-a.test", "GET", "/", nil)
				state := conn.ConnectionState()
				conn.Close()
				if err != nil {
					f.t.Fatal(err)
				}
				expected := 200
				if client == "unenrolled" {
					expected = 403
				}
				if res.StatusCode != expected {
					f.t.Fatal("resumption changed authorization", res.StatusCode)
				}
				if state.DidResume != (enabled && attempt == 1) {
					f.t.Fatalf("TLS=%x enabled=%v attempt=%d resumed=%v", version, enabled, attempt, state.DidResume)
				}
				_, ticket := cfg.ClientSessionCache.Get("app-a.test")
				if ticket != enabled {
					f.t.Fatalf("TLS=%x enabled=%v ticket=%v", version, enabled, ticket)
				}
			}
		}
	}
}

func TestTicketsEnabled(t *testing.T) { f := newFixture(t, false, true, true); f.testSessions(true) }
func TestNonStrictConflict(t *testing.T) {
	f := newFixture(t, false, false, false)
	f.expect("conflict.test", "conflict.test", "", tls.VersionTLS13, "GET", "/", 403, "unverified")
	routers := f.config["http"].(object)["routers"].(object)
	routers["conflict-d"].(object)["priority"] = 30
	f.save()
	f.await(func() bool {
		res, _, err := f.request("conflict.test", "conflict.test", "", tls.VersionTLS13, "GET", "/")
		return err == nil && res.StatusCode == 200
	})
}

func wsWrite(t *testing.T, conn net.Conn, payload string) {
	t.Helper()
	mask := []byte{1, 2, 3, 4}
	frame := append([]byte{0x81, 0x80 | byte(len(payload))}, mask...)
	for i := range payload {
		frame = append(frame, payload[i]^mask[i%4])
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
}
func wsRead(t *testing.T, r io.Reader, want string) {
	t.Helper()
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, int(header[1]&127))
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatal(err)
	}
	if header[0] != 0x81 || string(payload) != want {
		t.Fatal("bad websocket frame", header, string(payload))
	}
}
func TestStreamsAndPolicyReload(t *testing.T) {
	f := newFixture(t, false, true, false)
	for _, client := range []string{"alice", "unenrolled"} {
		conn, err := f.dial("app-a.test", client, tls.VersionTLS13, false)
		if err != nil {
			t.Fatal(err)
		}
		headers := http.Header{"Connection": []string{"Upgrade"}, "Upgrade": []string{"websocket"}, "Sec-WebSocket-Key": []string{"dGhlIHNhbXBsZSBub25jZQ=="}, "Sec-WebSocket-Version": []string{"13"}}
		req, _ := http.NewRequest("GET", "https://app-a.test/ws", nil)
		req.Header = headers
		if err := req.Write(conn); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(conn)
		res, err := http.ReadResponse(reader, req)
		if err != nil {
			t.Fatal(err)
		}
		if client == "unenrolled" {
			if res.StatusCode != 403 {
				t.Fatal(res.StatusCode)
			}
			res.Body.Close()
			conn.Close()
			continue
		}
		if res.StatusCode != 101 {
			t.Fatal(res.StatusCode)
		}
		keepalive, err := f.dial("app-a.test", "alice", tls.VersionTLS13, false)
		if err != nil {
			t.Fatal(err)
		}
		first, _, err := exchange(keepalive, "app-a.test", "GET", "/", nil)
		if err != nil || first.StatusCode != 200 {
			t.Fatal("initial keep-alive request", err)
		}
		wsWrite(t, conn, "before")
		wsRead(t, reader, "before")
		f.plugin("a")["policy"].(object)["identities"] = []string{}
		f.save()
		f.await(func() bool {
			res, _, err := f.request("app-a.test", "app-a.test", "alice", tls.VersionTLS13, "GET", "/")
			return err == nil && res.StatusCode == 403
		})
		next, _, err := exchange(keepalive, "app-a.test", "GET", "/", nil)
		keepalive.Close()
		if err != nil || next.StatusCode != 403 || next.Header.Get("X-Mtls-Authz-Reason") != "not_enrolled" {
			t.Fatalf("reload on existing connection: %v %v", next, err)
		}
		wsWrite(t, conn, "after")
		wsRead(t, reader, "after")
		conn.Close()
	}
	// Re-enable for a streaming upload and streaming response.
	f.plugin("a")["policy"].(object)["identities"] = []string{alice}
	f.save()
	f.await(func() bool {
		res, _, err := f.request("app-a.test", "app-a.test", "alice", tls.VersionTLS13, "GET", "/")
		return err == nil && res.StatusCode == 200
	})
	conn, err := f.dial("app-a.test", "alice", tls.VersionTLS13, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "POST /stream HTTP/1.1\r\nHost: app-a.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
	select {
	case <-f.streamStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("upload buffered before EOF")
	}
	fmt.Fprint(conn, "5\r\nworld\r\n0\r\n\r\n")
	res, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || string(body) != "received=10" {
		t.Fatalf("stream: %q %v", body, err)
	}
	events, err := f.dial("app-a.test", "alice", tls.VersionTLS13, false)
	if err != nil {
		t.Fatal(err)
	}
	defer events.Close()
	fmt.Fprint(events, "GET /events HTTP/1.1\r\nHost: app-a.test\r\n\r\n")
	res, err = http.ReadResponse(bufio.NewReader(events), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	reader := bufio.NewReader(res.Body)
	line, err := reader.ReadString('\n')
	if err != nil || line != "first\n" {
		t.Fatalf("flush: %q %v", line, err)
	}
	close(f.eventRelease)
	line, err = reader.ReadString('\n')
	if err != nil || line != "last\n" {
		t.Fatalf("flush: %q %v", line, err)
	}
}

func TestPluginLoadFailure(t *testing.T) {
	f := newFixture(t, false, true, false)
	if output, err := f.compose("down", "--timeout", "3"); err != nil {
		t.Fatal(err, string(output))
	}
	path := filepath.Join(f.dir, "static.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var static object
	if err := json.Unmarshal(data, &static); err != nil {
		t.Fatal(err)
	}
	static["experimental"].(object)["localPlugins"].(object)["traefik-mtls-authz"].(object)["moduleName"] = "invalid.example/missing-plugin"
	writeJSON(t, path, static)
	output, err := f.compose("up", "--abort-on-container-exit", "--exit-code-from", "traefik")
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("failed to open the plugin manifest")) {
		t.Fatalf("plugin failure must exit nonzero: %v\n%s", err, output)
	}
}

// Keep a connection established across a CA's expiry plus the 60-second skew.
// The leaf remains valid throughout; TLS has no further handshake to catch this.
func TestCAExpiryOnKeepAlive(t *testing.T) {
	f := newFixture(t, false, true, false)
	caExpiry := time.Now().Add(4 * time.Second).Truncate(time.Second)
	shortCA := issue(t, f.root, "short-intermediate", true, nil, nil, caExpiry)
	f.clients["short-ca"] = issue(t, shortCA, "long-leaf", false, []string{alice}, nil, time.Now().Add(time.Hour))
	conn, err := f.dial("app-a.test", "short-ca", tls.VersionTLS13, false)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	res, _, err := exchange(conn, "app-a.test", "GET", "/", nil)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("initial request: %v %v", res, err)
	}
	wait := time.Until(caExpiry.Add(60*time.Second + 100*time.Millisecond))
	t.Logf("waiting %s for CA expiry and clock skew", wait)
	for wait > 0 {
		step := wait
		if step > 30*time.Second {
			step = 30 * time.Second
		}
		time.Sleep(step)
		wait = time.Until(caExpiry.Add(60*time.Second + 100*time.Millisecond))
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	res, _, err = exchange(conn, "app-a.test", "GET", "/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 || res.Header.Get("X-Mtls-Authz-Reason") != "cert_time" {
		t.Fatal("expired CA accepted on keep-alive", res.StatusCode, res.Header)
	}
}

func TestDebugAllowLogging(t *testing.T) {
	f := fixtureWithLogLevel(t, false, true, false, "DEBUG")
	data, err := f.compose("logs", "--no-color")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, line := range bytes.Split(data, []byte("\n")) {
		if bytes.Contains(line, []byte("DBG ")) && bytes.Contains(line, []byte("event=allow reason=allowed")) {
			found = true
		}
	}
	if !found {
		t.Fatal("allow decision missing from DEBUG log")
	}

}

func TestCatalogConfiguration(t *testing.T) {
	f := newFixture(t, false, true, false)
	data, err := os.ReadFile("../.traefik.yml")
	if err != nil {
		t.Fatal(err)
	}
	_, literal, ok := strings.Cut(string(data), "  policyJSON: |\n")
	if !ok {
		t.Fatal("catalog must have a policyJSON testData literal")
	}
	var lines []string
	for _, line := range strings.Split(literal, "\n") {
		lines = append(lines, strings.TrimPrefix(line, "    "))
	}
	text := strings.Join(lines, "\n")
	var p object
	if err := json.Unmarshal([]byte(text), &p); err != nil {
		t.Fatal(err)
	}
	f.config["http"].(object)["middlewares"].(object)["catalog"] = object{"plugin": object{"traefik-mtls-authz": object{"policyJSON": text}}}
	f.config["http"].(object)["routers"].(object)["catalog"] = object{"rule": "Host(`catalog.test`)", "priority": 100, "entryPoints": []string{"web"}, "service": "backend", "middlewares": []string{"catalog"}, "tls": object{"options": "mtls-a"}}
	f.save()
	// The catalog's illustrative issuer cannot match our ephemeral CA, but this
	// reason proves its constructor succeeded and its handler was registered.
	f.await(func() bool {
		res, _, err := f.request("catalog.test", "catalog.test", "alice", tls.VersionTLS13, "GET", "/")
		return err == nil && res.Header.Get("X-Mtls-Authz-Reason") == "issuer_not_trusted"
	})
}

func TestJSONFileLogging(t *testing.T) {
	f := fixtureWithLogConfig(t, false, true, false, object{"level": "INFO", "format": "json", "filePath": "/logs/traefik.json"})
	f.expect("app-a.test", "app-a.test", "unenrolled", tls.VersionTLS13, "GET", "/", 403, "not_enrolled")
	f.await(func() bool {
		data, err := os.ReadFile(filepath.Join(f.dir, "logs", "traefik.json"))
		if err != nil {
			return false
		}
		load, invalid, deny := false, false, false
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte("\n")) {
			var entry object
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatalf("Traefik file log must remain valid JSON: %s", line)
			}
			message, _ := entry["message"].(string)
			if strings.Contains(message, "event=allow") {
				t.Fatal("allow leaked into INFO file log")
			}
			if !strings.Contains(message, "event=") {
				continue
			}
			if entry["level"] != "error" || entry["plugin"] != "plugin-traefik-mtls-authz" || entry["time"] == nil {
				t.Fatal("plugin log bypassed Traefik metadata", entry)
			}
			if strings.Contains(message, "event=load reason=ready") {
				load = true
			}
			if strings.Contains(message, "event=load reason=config_invalid") {
				invalid = true
			}
			if strings.Contains(message, "event=deny reason=not_enrolled") {
				deny = true
			}
		}
		return load && invalid && deny
	})
	console, err := f.compose("logs", "--no-color")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(console, []byte("event=deny")) || bytes.Contains(console, []byte("event=load")) {
		t.Fatal("plugin events bypassed the configured file sink")
	}
}

func TestHTTP2Authorization(t *testing.T) {
	f := newFixture(t, false, true, false)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, tc := range []struct {
			host, client, reason, identity string
			status                         int
		}{
			{"app-a.test", "alice", "", alice, 200},
			{"app-a.test", "unenrolled", "not_enrolled", "", 403},
			{"app-a.test", "registered-id", "identity_ambiguous", "", 403},
			{"app-a.test", "unknown-san", "identity_invalid", "", 403},
			{"app-b.test", "bob", "", "", 200},
		} {
			cfg := f.tlsConfig(tc.host, tc.client, version)
			cfg.NextProtos = []string{"h2"}
			transport := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", f.address)
			}}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			req, err := http.NewRequest("GET", "https://"+tc.host+"/", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header = http.Header{"X-Mtls-Identity": []string{bob}, "X-Mtls-Forged": []string{"spoof"}, "X-Forwarded-Tls-Client-Cert": []string{"spoof"}, "X-Forwarded-Tls-Client-Cert-Info": []string{"spoof"}}
			res, err := client.Do(req)
			if err != nil {
				transport.CloseIdleConnections()
				t.Fatal(err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			transport.CloseIdleConnections()
			if err != nil {
				t.Fatal(err)
			}
			if res.ProtoMajor != 2 || res.TLS == nil || res.TLS.NegotiatedProtocol != "h2" || res.TLS.Version != version {
				t.Fatal("request did not use HTTP/2 on the expected TLS version", res.Proto, res.TLS)
			}
			if res.StatusCode != tc.status || res.Header.Get("X-Mtls-Authz-Reason") != tc.reason {
				t.Fatalf("HTTP/2 %s: status=%d reason=%s", tc.client, res.StatusCode, res.Header.Get("X-Mtls-Authz-Reason"))
			}
			if tc.status == 200 {
				f.assertBackendHeaders(body, tc.identity)
			} else if string(body) != "forbidden\n" || res.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("bad HTTP/2 deny response")
			}
		}
	}
}

func TestPluginCompileFailure(t *testing.T) {
	f := newFixture(t, false, true, false)
	if output, err := f.compose("down", "--timeout", "3"); err != nil {
		t.Fatal(err, string(output))
	}
	// A separate temporary source mount prevents mutation of the working plugin.
	f.source = filepath.Join(f.dir, "compile-failure")
	if err := os.Mkdir(f.source, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", ".traefik.yml"} {
		data, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.source, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Valid Go syntax with an undefined identifier exercises Yaegi compilation.
	source := "package traefik_mtls_authz\nvar broken = undefinedCompileFixtureIdentifier\n"
	if err := os.WriteFile(filepath.Join(f.source, "broken.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := f.compose("up", "--abort-on-container-exit", "--exit-code-from", "traefik")
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !bytes.Contains(output, []byte("failed to create plugin builder")) || !bytes.Contains(output, []byte("failed to import plugin code")) || !bytes.Contains(output, []byte("broken.go")) {
		t.Fatalf("Yaegi compile failure must exit nonzero: %v\n%s", err, output)
	}
}
