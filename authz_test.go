package traefikmtlsauthz

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSkeletonAlwaysDenies(t *testing.T) {
	for _, name := range []string{"plain-http", "forged-header", "peer-certificate", "verified-chain"} {
		t.Run(name, func(t *testing.T) {
			reached := false
			handler, err := New(context.Background(), http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }), CreateConfig(), "test")
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			cert := &x509.Certificate{}
			switch name {
			case "forged-header":
				req.Header.Set("X-Forwarded-Tls-Client-Cert", "trusted-device")
			case "peer-certificate":
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
			case "verified-chain":
				req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusForbidden || reached {
				t.Fatalf("status=%d downstream=%v", response.Code, reached)
			}
		})
	}
}
