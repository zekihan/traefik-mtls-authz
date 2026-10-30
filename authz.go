// Package traefik_mtls_authz authorizes verified client certificates per application.
// Certificate verification belongs to Traefik's RequireAndVerifyClientCert TLS option.
package traefik_mtls_authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// Traefik virtualizes log.Writer for Yaegi. Keep a private logger so the plugin
// neither changes the host logger nor bypasses its JSON/file/level settings.
var decisionLogger = log.New(log.Writer(), "", 0)

// CreateConfig preserves raw types and unknown keys through Traefik's weak decoder.
// An empty configuration deliberately fails in New.
func CreateConfig() *map[string]interface{} {
	return &map[string]interface{}{}
}

// Middleware is an immutable policy snapshot. Reloads create a new instance;
// existing streams are not revoked by a policy reload.
type Middleware struct {
	next                                   http.Handler
	policy                                 policy
	name                                   string
	issuers, identities, disabled, blocked map[string]bool
	now                                    func() time.Time
}

// New validates the complete policy before accepting any requests. It performs
// no network or filesystem reads and retains no references to the input map.
func New(_ context.Context, next http.Handler, cfg *map[string]interface{}, name string) (http.Handler, error) {
	p, err := parsePolicy(cfg)
	if err != nil {
		decisionLogger.Printf("event=load reason=config_invalid app=%q policyRevision=%q router=%q error=%q\n", p.App, p.PolicyRevision, name, err.Error())
		return nil, err
	}
	if next == nil {
		err = fmt.Errorf("next handler is required")
		decisionLogger.Printf("event=load reason=config_invalid app=%q policyRevision=%q router=%q error=%q\n", p.App, p.PolicyRevision, name, err.Error())
		return nil, err
	}
	m := &Middleware{next: next, policy: p, name: name, now: time.Now,
		issuers: stringSet(p.TrustedIssuers), identities: stringSet(p.Identities),
		disabled: stringSet(p.DisabledIdentities), blocked: make(map[string]bool)}
	for _, entry := range p.BlockedFingerprints {
		m.blocked[entry.Fingerprint] = true
	}
	reason := "ready"
	if len(m.identities) == 0 {
		reason = "empty_allowlist"
	}
	decisionLogger.Printf("event=load reason=%s app=%q policyRevision=%q router=%q identities=%d\n", reason, p.App, p.PolicyRevision, name, len(m.identities))
	return m, nil
}

func stringSet(values []string) map[string]bool {
	set := make(map[string]bool)
	for _, value := range values {
		set[value] = true
	}
	return set
}

func fingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

type decision struct{ reason, identity, leafFp, anchorFp string }

func (m *Middleware) authorize(req *http.Request) decision {
	d := decision{reason: "no_tls"}
	if req.TLS == nil {
		return d
	}
	d.reason = "unverified"
	if len(req.TLS.VerifiedChains) == 0 || len(req.TLS.VerifiedChains[0]) == 0 ||
		len(req.TLS.PeerCertificates) == 0 || req.TLS.PeerCertificates[0] == nil {
		return d
	}
	chain := req.TLS.VerifiedChains[0]
	// Synthetic or corrupted TLS state must also fail closed.
	for _, cert := range chain {
		if cert == nil || len(cert.Raw) == 0 {
			return d
		}
	}
	leaf := chain[0]
	if !bytes.Equal(leaf.Raw, req.TLS.PeerCertificates[0].Raw) {
		return d
	}
	d.leafFp = fingerprint(leaf.Raw)
	d.anchorFp = fingerprint(chain[len(chain)-1].Raw)
	d.reason = "issuer_not_trusted"
	if !m.issuers[d.anchorFp] {
		return d
	}
	d.reason = "cert_time"
	now := m.now()
	for _, cert := range chain {
		if now.Before(cert.NotBefore.Add(-60*time.Second)) || now.After(cert.NotAfter.Add(60*time.Second)) {
			return d
		}
	}
	d.reason = "fingerprint_blocked"
	if m.blocked[d.leafFp] {
		return d
	}
	d.reason = "identity_missing"
	if len(leaf.URIs) == 0 {
		return d
	}
	d.reason = "identity_ambiguous"
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return d
	}
	d.reason = "identity_invalid"
	if leaf.URIs[0] == nil {
		return d
	}
	rawIdentity, reason := rawURIIdentity(leaf)
	if reason != "" {
		d.reason = reason
		return d
	}
	d.identity = rawIdentity
	if rawIdentity != leaf.URIs[0].String() || !validIdentity(d.identity, m.policy.IdentityPrefix) {
		return d
	}
	d.reason = "identity_disabled"
	if m.disabled[d.identity] {
		return d
	}
	d.reason = "not_enrolled"
	if !m.identities[d.identity] {
		return d
	}
	if rule, ok := m.policy.Constraints[d.identity]; ok {
		d.reason = "constraint_method"
		if !contains(rule.Methods, req.Method) {
			return d
		}
		d.reason = "constraint_path"
		if req.URL == nil || req.URL.EscapedPath() != req.URL.Path || !contains(rule.Paths, req.URL.Path) {
			return d
		}
	}
	d.reason = "allowed"
	return d
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// ServeHTTP authorizes each request without reading its body or wrapping w.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	d := m.authorize(req)
	if d.reason != "allowed" {
		m.logDecision("deny", d, req)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Mtls-Authz-Reason", d.reason)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Header.Del alone misses noncanonical keys from another middleware.
	for key := range req.Header {
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "x-mtls-") || lower == "x-forwarded-tls-client-cert" || lower == "x-forwarded-tls-client-cert-info" {
			delete(req.Header, key)
		}
	}
	if m.policy.ForwardIdentityHeader != "" {
		for key := range req.Header {
			if strings.EqualFold(key, m.policy.ForwardIdentityHeader) {
				delete(req.Header, key)
			}
		}
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set(m.policy.ForwardIdentityHeader, d.identity)
	}
	m.logDecision("allow", d, req)
	m.next.ServeHTTP(w, req)
}

func (m *Middleware) logDecision(event string, d decision, req *http.Request) {
	version := uint16(0)
	sni, path := "", ""
	if req.TLS != nil {
		version, sni = req.TLS.Version, req.TLS.ServerName
	}
	if req.URL != nil {
		path = req.URL.Path
	}
	leafFp, anchorFp := d.leafFp, d.anchorFp
	if len(leafFp) > 16 {
		leafFp = leafFp[:16]
	}
	if len(anchorFp) > 16 {
		anchorFp = anchorFp[:16]
	}
	// Identity syntax validation can reject a large CA-issued URI. Bound its
	// log representation independently so that certificate cannot flood logs.
	identity := d.identity
	if len(identity) > 128 {
		identity = identity[:128] + "[truncated]"
	}
	// Quoting keeps attacker-controlled strings on one line. No query strings,
	// certificate bodies, request bodies or headers are logged.
	line := fmt.Sprintf("event=%s reason=%s app=%q policyRevision=%q router=%q identity=%q leafFp=%q anchorFp=%q tlsVersion=0x%04x sni=%q host=%q method=%q path=%q\n",
		event, d.reason, m.policy.App, m.policy.PolicyRevision, m.name, identity, leafFp, anchorFp, version, sni, req.Host, req.Method, path)
	if event == "allow" {
		// Yaegi routes fmt.Print through the interpreter's DEBUG-level stdout.
		// Writing os.Stdout directly would bypass Traefik's log-level filtering.
		fmt.Print(line)
	} else {
		// Yaegi routes log.Print through Traefik's ERROR writer, including
		// JSON formatting and log.filePath. Raw os.Stderr would bypass it.
		decisionLogger.Print(line)
	}
}
