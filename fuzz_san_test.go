package traefik_mtls_authz

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func seedSANs() [][]byte {
	general := func(names ...asn1.RawValue) []byte {
		data, err := asn1.Marshal(names)
		if err != nil {
			panic(err)
		}
		return data
	}
	uri := func(s string) asn1.RawValue { return asn1.RawValue{Class: 2, Tag: 6, Bytes: []byte(s)} }
	canonical := canonicalSAN(testIdentity)
	long := append([]byte{0x30, 0x81, byte(len(canonical) - 2)}, canonical[2:]...)
	innerLong := append([]byte{0x30, byte(len(canonical) - 1), 0x86, 0x81, byte(len(testIdentity))}, testIdentity...)
	highTag := append([]byte{0x30, byte(len(canonical) - 1), 0x9f, 0x06, byte(len(testIdentity))}, testIdentity...)
	indefinite := append(append([]byte{0x30, 0x80}, canonical[2:]...), 0, 0)
	set := append([]byte{0x31}, canonical[1:]...)
	return [][]byte{
		canonical, long, innerLong, highTag, indefinite, set,
		append(append([]byte{}, canonical...), 0),
		canonicalSAN("URN:noqer:mtls:clients:alice"),
		canonicalSAN("urn:noqer:mtls:clients:%61lice"),
		canonicalSAN("urn:noqer:mtls:clients:alice#x"),
		canonicalSAN("urn:noqer:mtls:clients:alice?x"),
		canonicalSAN("urn:noqer:mtls:clients:bob"),
		canonicalSAN("urn:noqer:mtls:clients:" + strings.Repeat("a", 105)),
		canonicalSAN("urn:noqer:mtls:clients:" + strings.Repeat("a", 106)),
		general(uri(testIdentity), uri(testIdentity)),
		general(uri(testIdentity), asn1.RawValue{Class: 2, Tag: 2, Bytes: []byte("app.test")}),
		general(asn1.RawValue{Class: 2, Tag: 8, Bytes: []byte{0x2a, 0x03}}, uri(testIdentity)),
		general(uri(testIdentity), asn1.RawValue{Class: 2, Tag: 9, Bytes: []byte{1}}),
		general(asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: []byte{0x06, 0x01, 0x2a, 0xa0, 0x02, 0x0c, 0x00}}, uri(testIdentity)),
		general(asn1.RawValue{Class: 2, Tag: 6, IsCompound: true, Bytes: []byte{0x16, 0x01, 'a'}}),
		general(asn1.RawValue{Class: 0, Tag: 22, Bytes: []byte(testIdentity)}),
		{0x30, 0x00}, {0x04, 0x00}, {},
	}
}

// FuzzRawSAN differential-tests rawURIIdentity (encoding/asn1 based) against
// an independent strict DER reader, with zero, one or two SAN extensions and
// unrelated extensions around them. A successful extraction must also be the
// one canonical DER encoding of that identity.
func FuzzRawSAN(f *testing.F) {
	for i, s := range seedSANs() {
		f.Add(s, canonicalSAN("urn:noqer:mtls:clients:bob"), byte(i))
	}
	f.Fuzz(func(t *testing.T, a, b []byte, mode byte) {
		san := pkix.Extension{Id: oidSAN, Value: a}
		other := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: b}
		var exts []pkix.Extension
		switch mode % 6 {
		case 0:
			exts = []pkix.Extension{san}
		case 1:
			exts = []pkix.Extension{san, {Id: oidSAN, Value: b}}
		case 2:
			exts = []pkix.Extension{other, san}
		case 3:
			exts = []pkix.Extension{san, other, {Id: asn1.ObjectIdentifier{2, 5, 29, 17, 1}, Value: b}}
		case 4:
			exts = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29}, Value: a}}
		case 5:
			exts = nil
		}
		identity, reason := rawURIIdentity(&x509.Certificate{Extensions: exts})
		refID, refReason := refSAN(exts)
		if identity != refID || reason != refReason {
			t.Fatalf("rawURIIdentity=(%q,%q) reference=(%q,%q) exts=%v", identity, reason, refID, refReason, exts)
		}
		if reason == "" && string(a) != string(canonicalSAN(identity)) {
			t.Fatalf("accepted non-canonical SAN encoding %x for %q", a, identity)
		}
	})
}

var fuzzLeafKey = ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

// fuzzX509Policy enrolls alice and bob, disables carol and pins fuzzRootRaw.
func fuzzX509Middleware(t *testing.T) (*Middleware, refPolicy) {
	cfg := map[string]interface{}{"policy": map[string]interface{}{
		"schemaVersion": 1, "app": "fuzz", "trustedIssuers": []string{refFingerprint(fuzzRootRaw)},
		"identityPrefix":     "urn:noqer:mtls:clients:",
		"identities":         []string{testIdentity, "urn:noqer:mtls:clients:bob", "urn:noqer:mtls:clients:carol"},
		"disabledIdentities": []string{"urn:noqer:mtls:clients:carol"},
	}}
	h, err := New(context.Background(), http.NotFoundHandler(), &cfg, "fuzz")
	if err != nil {
		t.Fatal(err)
	}
	m := h.(*Middleware)
	m.now = func() time.Time { return testNow }
	return m, refPolicyFromParsed(m.policy)
}

// FuzzAuthorizeX509 issues a real certificate with crypto/x509 whose SAN,
// subject and other extensions are attacker controlled, parses it back the
// way crypto/tls does, and authorizes it. Properties: the decision equals the
// reference decision, and any allow satisfies checkAllowInvariant (the SAN is
// the canonical encoding of an enrolled, non-disabled identity). In
// particular, no subject/CN, DNS, e-mail or alternate URI spelling of an
// enrolled identity may be allowed.
func FuzzAuthorizeX509(f *testing.F) {
	quietFuzzLogs(f)
	for i, s := range seedSANs() {
		f.Add(s, testIdentity, byte(i), "urn:noqer:mtls:clients:alice")
	}
	f.Add([]byte{}, "alice", byte(1), "URN:noqer:mtls:clients:alice")
	f.Add([]byte{}, "urn:noqer:mtls:clients:alice", byte(3), "urn:noqer:mtls:clients:alice")
	f.Add([]byte{}, "x", byte(5), "urn:noqer:mtls:clients:%61lice")
	f.Add([]byte{}, "x", byte(7), "app.test")
	f.Fuzz(func(t *testing.T, san []byte, cn string, mode byte, aux string) {
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(mode) + 1), Subject: pkix.Name{CommonName: cn},
			NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		switch mode % 8 {
		case 0, 4, 6:
			tpl.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Critical: mode&0x10 != 0, Value: san}}
		case 1, 5:
			u, err := url.Parse(aux)
			if err != nil {
				t.Skip()
			}
			tpl.URIs = []*url.URL{u}
		case 2:
			tpl.ExtraExtensions = []pkix.Extension{{Id: oidSAN, Value: san}}
			tpl.DNSNames = []string{aux}
		case 3:
			tpl.EmailAddresses = []string{aux}
			if u, err := url.Parse(aux); err == nil {
				tpl.URIs = []*url.URL{u}
			}
		case 7:
			tpl.DNSNames = []string{aux}
		}
		if mode&0x20 != 0 {
			tpl.ExtraExtensions = append(tpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: san})
		}
		der, err := x509.CreateCertificate(fuzzZeroReader{}, tpl, tpl, fuzzLeafKey.Public(), fuzzLeafKey)
		if err != nil {
			t.Skip()
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Skip() // crypto/tls rejects the handshake before the plugin runs
		}
		m, rp := fuzzX509Middleware(t)
		req := httptest.NewRequest("GET", "https://app.test/", nil)
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, fuzzCert(fuzzRootRaw)}}}
		d := m.authorize(req)
		if want := refDecide(rp, req, testNow); d.reason != want {
			t.Fatalf("plugin=%s reference=%s uris=%v dns=%v", d.reason, want, leaf.URIs, leaf.DNSNames)
		}
		checkAllowInvariant(t, rp, req, testNow, d)
	})
}

type fuzzZeroReader struct{}

func (fuzzZeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
