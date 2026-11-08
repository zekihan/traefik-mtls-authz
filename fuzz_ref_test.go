package traefik_mtls_authz

// Independent reference implementations used as fuzzing oracles. They are
// written from docs/design.md, not from the production code, and deliberately
// avoid the production regular expressions, encoding/asn1 and encoding/json
// tokenization so that a parser bug cannot be mirrored into its own oracle.

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// fuzzBytes turns an arbitrary byte string into a stream of structured choices.
type fuzzBytes struct{ data []byte }

func (b *fuzzBytes) next() byte {
	if len(b.data) == 0 {
		return 0
	}
	c := b.data[0]
	b.data = b.data[1:]
	return c
}

func (b *fuzzBytes) flag() bool     { return b.next()&1 == 1 }
func (b *fuzzBytes) intn(n int) int { return int(b.next()) % n }

// quietFuzzLogs discards decision logs. Allow decisions use fmt.Print, so the
// fuzz worker's stdout is redirected too; both are restored after the target.
func quietFuzzLogs(f *testing.F) {
	savedLog, savedStdout := decisionLogger.Writer(), os.Stdout
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		f.Fatal(err)
	}
	decisionLogger.SetOutput(io.Discard)
	os.Stdout = null
	f.Cleanup(func() {
		decisionLogger.SetOutput(savedLog)
		os.Stdout = savedStdout
		_ = null.Close()
	})
}

func refFingerprint(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func refLowerAlnum(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }

// refIdentity implements design section 4: urn:noqer:mtls:<profile>:<name>,
// at most 128 bytes, inside prefix. profile is hyphen-separated lowercase
// alphanumeric words; name is lowercase alphanumeric with inner hyphens.
func refIdentity(s, prefix string) bool {
	const head = "urn:noqer:mtls:"
	if len(s) > 128 || !strings.HasPrefix(s, prefix) || !strings.HasPrefix(s, head) {
		return false
	}
	rest := s[len(head):]
	colon := strings.IndexByte(rest, ':')
	if colon <= 0 {
		return false
	}
	profile, name := rest[:colon], rest[colon+1:]
	for _, word := range strings.Split(profile, "-") {
		if word == "" {
			return false
		}
		for i := 0; i < len(word); i++ {
			if !refLowerAlnum(word[i]) {
				return false
			}
		}
	}
	if name == "" || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		if !refLowerAlnum(name[i]) && name[i] != '-' {
			return false
		}
	}
	return true
}

func refPrefix(prefix string) bool {
	const head = "urn:noqer:mtls:"
	if !strings.HasPrefix(prefix, head) || !strings.HasSuffix(prefix, ":") || len(prefix) < len(head)+2 {
		return false
	}
	// The prefix must be exactly one profile namespace: a valid identity is
	// obtained by appending a one-character name.
	return strings.Count(prefix, ":") == 4 && refIdentity(prefix+"x", prefix)
}

func refHexFingerprint(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune("0123456789abcdef", rune(s[i])) {
			return false
		}
	}
	return true
}

func refDate(s string) bool {
	if len(s) != 10 || s[4] != '-' || s[7] != '-' {
		return false
	}
	num := func(t string) (int, bool) {
		n := 0
		for i := 0; i < len(t); i++ {
			if t[i] < '0' || t[i] > '9' {
				return 0, false
			}
			n = n*10 + int(t[i]-'0')
		}
		return n, true
	}
	year, ok1 := num(s[:4])
	month, ok2 := num(s[5:7])
	day, ok3 := num(s[8:])
	if !ok1 || !ok2 || !ok3 || month < 1 || month > 12 || day < 1 {
		return false
	}
	days := []int{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[month-1]
	if month == 2 && year%4 == 0 && (year%100 != 0 || year%400 == 0) {
		days = 29
	}
	return day <= days
}

var refMethods = []string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

// refPathByte is RFC 3986 pchar minus pct-encoded, plus '/'. Brackets are
// accepted because Go's url package leaves them literal (see docs/fuzzing.md).
func refPathByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		strings.IndexByte("-._~!$&'()*+,;=:@/[]", c) >= 0
}

// refConstraintPath: absolute, exact, literal (no percent encoding), no
// trailing slash except "/", no "//" and no ".." anywhere.
func refConstraintPath(p string) bool {
	if p == "" || p[0] != '/' || strings.Contains(p, "//") || strings.Contains(p, "..") || (p != "/" && strings.HasSuffix(p, "/")) {
		return false
	}
	for i := 0; i < len(p); i++ {
		if !refPathByte(p[i]) {
			return false
		}
	}
	return true
}

const refTokenChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-.^_`|~"

func refHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !strings.ContainsRune(refTokenChars, rune(s[i])) {
			return false
		}
	}
	return true
}

func refForwardHeader(s string) bool {
	return s == "" || (refHeaderToken(s) && len(s) > len("x-mtls-") && strings.EqualFold(s[:len("x-mtls-")], "x-mtls-"))
}

// ---------------------------------------------------------------------------
// Strict DER TLV reader (X.690 DER) independent of encoding/asn1.

type refTLV struct {
	class       int
	constructed bool
	tag         int
	content     []byte
}

func refReadTLV(b []byte) (refTLV, []byte, bool) {
	var t refTLV
	if len(b) < 2 {
		return t, nil, false
	}
	t.class = int(b[0] >> 6)
	t.constructed = b[0]&0x20 != 0
	t.tag = int(b[0] & 0x1f)
	i := 1
	if t.tag == 0x1f {
		t.tag = 0
		for n := 0; ; n++ {
			if i >= len(b) || n == 4 {
				return t, nil, false
			}
			c := b[i]
			i++
			if n == 0 && c == 0x80 {
				return t, nil, false
			}
			t.tag = t.tag<<7 | int(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if t.tag < 0x1f {
			return t, nil, false
		}
	}
	if i >= len(b) {
		return t, nil, false
	}
	length := int(b[i])
	i++
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 3 {
			return t, nil, false
		}
		length = 0
		for j := 0; j < n; j++ {
			if i >= len(b) || (j == 0 && b[i] == 0) {
				return t, nil, false
			}
			length = length<<8 | int(b[i])
			i++
		}
		if length < 0x80 {
			return t, nil, false
		}
	}
	if length > len(b)-i {
		return t, nil, false
	}
	t.content = b[i : i+length]
	return t, b[i+length:], true
}

var oidSAN = asn1.ObjectIdentifier{2, 5, 29, 17}

// refSAN extracts the single URI GeneralName from the raw SAN extension
// following design section 3 step 7.
func refSAN(exts []pkix.Extension) (string, string) {
	var sans [][]byte
	for _, e := range exts {
		if e.Id.Equal(oidSAN) {
			sans = append(sans, e.Value)
		}
	}
	if len(sans) != 1 {
		return "", "identity_invalid"
	}
	seq, rest, ok := refReadTLV(sans[0])
	if !ok || len(rest) != 0 || seq.class != 0 || seq.tag != 16 || !seq.constructed {
		return "", "identity_invalid"
	}
	names, entries, uris, identity := seq.content, 0, 0, ""
	for len(names) > 0 {
		name, rest, ok := refReadTLV(names)
		if !ok || name.class != 2 || name.tag > 8 {
			return "", "identity_invalid"
		}
		entries++
		if name.tag == 6 {
			if name.constructed {
				return "", "identity_invalid"
			}
			uris++
			identity = string(name.content)
		}
		names = rest
	}
	if uris == 0 {
		return "", "identity_invalid"
	}
	if entries != 1 {
		return "", "identity_ambiguous"
	}
	return identity, ""
}

// canonicalSAN is the only DER encoding of a SAN with one URI GeneralName.
func canonicalSAN(identity string) []byte {
	der := func(tag byte, content []byte) []byte {
		n := len(content)
		switch {
		case n < 0x80:
			return append([]byte{tag, byte(n)}, content...)
		case n < 0x100:
			return append([]byte{tag, 0x81, byte(n)}, content...)
		case n < 0x10000:
			return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, content...)
		default:
			return append([]byte{tag, 0x83, byte(n >> 16), byte(n >> 8), byte(n)}, content...)
		}
	}
	return der(0x30, der(0x86, []byte(identity)))
}

// ---------------------------------------------------------------------------
// Reference policy and decision.

type refPolicy struct {
	prefix              string
	trusted, identities map[string]bool
	disabled, blocked   map[string]bool
	constraints         map[string]constraint
}

func refNanos(t time.Time) *big.Int {
	n := big.NewInt(t.Unix())
	n.Mul(n, big.NewInt(1e9))
	return n.Add(n, big.NewInt(int64(t.Nanosecond())))
}

// refTimeValid: NotBefore-60s <= now <= NotAfter+60s, in exact arithmetic.
func refTimeValid(now, notBefore, notAfter time.Time) bool {
	skew := big.NewInt(60e9)
	n := refNanos(now)
	lo := new(big.Int).Sub(refNanos(notBefore), skew)
	hi := new(big.Int).Add(refNanos(notAfter), skew)
	return n.Cmp(lo) >= 0 && n.Cmp(hi) <= 0
}

func refDecide(rp refPolicy, req *http.Request, now time.Time) string {
	st := req.TLS
	if st == nil {
		return "no_tls"
	}
	if len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) == 0 || len(st.PeerCertificates) == 0 || st.PeerCertificates[0] == nil {
		return "unverified"
	}
	chain := st.VerifiedChains[0]
	for _, c := range chain {
		if c == nil || len(c.Raw) == 0 {
			return "unverified"
		}
	}
	leaf := chain[0]
	if string(leaf.Raw) != string(st.PeerCertificates[0].Raw) {
		return "unverified"
	}
	if !rp.trusted[refFingerprint(chain[len(chain)-1].Raw)] {
		return "issuer_not_trusted"
	}
	for _, c := range chain {
		if !refTimeValid(now, c.NotBefore, c.NotAfter) {
			return "cert_time"
		}
	}
	if rp.blocked[refFingerprint(leaf.Raw)] {
		return "fingerprint_blocked"
	}
	if len(leaf.URIs) == 0 {
		return "identity_missing"
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		return "identity_ambiguous"
	}
	if leaf.URIs[0] == nil {
		return "identity_invalid"
	}
	identity, reason := refSAN(leaf.Extensions)
	if reason != "" {
		return reason
	}
	if identity != leaf.URIs[0].String() || !refIdentity(identity, rp.prefix) {
		return "identity_invalid"
	}
	if rp.disabled[identity] {
		return "identity_disabled"
	}
	if !rp.identities[identity] {
		return "not_enrolled"
	}
	if rule, ok := rp.constraints[identity]; ok {
		methodOK := false
		for _, m := range rule.Methods {
			methodOK = methodOK || m == req.Method
		}
		if !methodOK {
			return "constraint_method"
		}
		if req.URL == nil || req.URL.EscapedPath() != req.URL.Path {
			return "constraint_path"
		}
		pathOK := false
		for _, p := range rule.Paths {
			pathOK = pathOK || p == req.URL.Path
		}
		if !pathOK {
			return "constraint_path"
		}
	}
	return "allowed"
}

// checkAllowInvariant is the security oracle: whatever the reason codes say,
// an allow must be justified by verified TLS evidence that independently
// satisfies every policy condition.
func checkAllowInvariant(t *testing.T, rp refPolicy, req *http.Request, now time.Time, d decision) {
	t.Helper()
	if d.reason != "allowed" {
		return
	}
	fail := func(why string) { t.Fatalf("authorization bypass: allowed but %s (identity=%q)", why, d.identity) }
	st := req.TLS
	if st == nil || len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) == 0 || len(st.PeerCertificates) == 0 {
		fail("no verified chain")
	}
	chain := st.VerifiedChains[0]
	leaf := chain[0]
	if st.PeerCertificates[0] == nil || string(leaf.Raw) != string(st.PeerCertificates[0].Raw) {
		fail("leaf is not the peer certificate")
	}
	if !rp.trusted[refFingerprint(chain[len(chain)-1].Raw)] {
		fail("anchor not pinned")
	}
	for _, c := range chain {
		if c == nil || len(c.Raw) == 0 || !refTimeValid(now, c.NotBefore, c.NotAfter) {
			fail("chain certificate missing or outside validity")
		}
	}
	if rp.blocked[refFingerprint(leaf.Raw)] {
		fail("leaf fingerprint blocked")
	}
	var sans []pkix.Extension
	for _, e := range leaf.Extensions {
		if e.Id.Equal(oidSAN) {
			sans = append(sans, e)
		}
	}
	if len(sans) != 1 || string(sans[0].Value) != string(canonicalSAN(d.identity)) {
		fail("SAN extension is not the canonical single-URI encoding of the identity")
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0] == nil || leaf.URIs[0].String() != d.identity || len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
		fail("parsed SAN fields disagree with the identity")
	}
	if !refIdentity(d.identity, rp.prefix) || !rp.identities[d.identity] || rp.disabled[d.identity] {
		fail("identity not enrolled, disabled, or malformed")
	}
	if rule, ok := rp.constraints[d.identity]; ok {
		if req.URL == nil || req.URL.EscapedPath() != req.URL.Path {
			fail("constrained path is not literal")
		}
		okMethod, okPath := false, false
		for _, m := range rule.Methods {
			okMethod = okMethod || m == req.Method
		}
		for _, p := range rule.Paths {
			okPath = okPath || p == req.URL.Path
		}
		if !okMethod || !okPath {
			fail("constraint not satisfied")
		}
	}
}

// ---------------------------------------------------------------------------
// Strict RFC 8259 JSON reader. Strings are decoded the way Go's encoding/json
// decodes them (invalid UTF-8 and lone surrogates become U+FFFD), because the
// plugin's semantics are defined on the decoded values.

type refJSON struct {
	kind  byte // o a s n t f z
	keys  []string
	vals  []*refJSON
	str   string
	num   string
	elems []*refJSON
}

type refJSONParser struct {
	s     []byte
	i     int
	depth int
}

func refParseJSON(data []byte) (*refJSON, bool) {
	p := &refJSONParser{s: data}
	v, ok := p.value()
	if !ok {
		return nil, false
	}
	p.ws()
	return v, p.i == len(p.s)
}

func (p *refJSONParser) ws() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

func (p *refJSONParser) lit(word string) bool {
	if strings.HasPrefix(string(p.s[p.i:]), word) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *refJSONParser) value() (*refJSON, bool) {
	p.ws()
	if p.i >= len(p.s) {
		return nil, false
	}
	switch c := p.s[p.i]; {
	case c == '{':
		p.depth++
		if p.depth > 10000 {
			return nil, false
		}
		p.i++
		v := &refJSON{kind: 'o'}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			p.depth--
			return v, true
		}
		for {
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != '"' {
				return nil, false
			}
			key, ok := p.str()
			if !ok {
				return nil, false
			}
			p.ws()
			if p.i >= len(p.s) || p.s[p.i] != ':' {
				return nil, false
			}
			p.i++
			val, ok := p.value()
			if !ok {
				return nil, false
			}
			v.keys = append(v.keys, key)
			v.vals = append(v.vals, val)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				p.depth--
				return v, true
			}
			return nil, false
		}
	case c == '[':
		p.depth++
		if p.depth > 10000 {
			return nil, false
		}
		p.i++
		v := &refJSON{kind: 'a'}
		p.ws()
		if p.i < len(p.s) && p.s[p.i] == ']' {
			p.i++
			p.depth--
			return v, true
		}
		for {
			e, ok := p.value()
			if !ok {
				return nil, false
			}
			v.elems = append(v.elems, e)
			p.ws()
			if p.i < len(p.s) && p.s[p.i] == ',' {
				p.i++
				continue
			}
			if p.i < len(p.s) && p.s[p.i] == ']' {
				p.i++
				p.depth--
				return v, true
			}
			return nil, false
		}
	case c == '"':
		s, ok := p.str()
		return &refJSON{kind: 's', str: s}, ok
	case c == 't' && p.lit("true"):
		return &refJSON{kind: 't'}, true
	case c == 'f' && p.lit("false"):
		return &refJSON{kind: 'f'}, true
	case c == 'n' && p.lit("null"):
		return &refJSON{kind: 'z'}, true
	case c == '-' || (c >= '0' && c <= '9'):
		start := p.i
		digits := func() int {
			n := 0
			for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
				p.i++
				n++
			}
			return n
		}
		if p.s[p.i] == '-' {
			p.i++
		}
		if p.i < len(p.s) && p.s[p.i] == '0' {
			p.i++
		} else if digits() == 0 {
			return nil, false
		}
		if p.i < len(p.s) && p.s[p.i] == '.' {
			p.i++
			if digits() == 0 {
				return nil, false
			}
		}
		if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
			p.i++
			if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
				p.i++
			}
			if digits() == 0 {
				return nil, false
			}
		}
		return &refJSON{kind: 'n', num: string(p.s[start:p.i])}, true
	}
	return nil, false
}

func (p *refJSONParser) str() (string, bool) {
	p.i++ // opening quote
	var out []rune
	hex4 := func() (rune, bool) {
		if p.i+4 > len(p.s) {
			return 0, false
		}
		var r rune
		for _, c := range p.s[p.i : p.i+4] {
			r <<= 4
			switch {
			case c >= '0' && c <= '9':
				r |= rune(c - '0')
			case c >= 'a' && c <= 'f':
				r |= rune(c-'a') + 10
			case c >= 'A' && c <= 'F':
				r |= rune(c-'A') + 10
			default:
				return 0, false
			}
		}
		p.i += 4
		return r, true
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), true
		case c < 0x20:
			return "", false
		case c == '\\':
			p.i++
			if p.i >= len(p.s) {
				return "", false
			}
			e := p.s[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, rune(e))
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, ok := hex4()
				if !ok {
					return "", false
				}
				if utf16.IsSurrogate(r) {
					save := p.i
					if p.i+2 <= len(p.s) && p.s[p.i] == '\\' && p.s[p.i+1] == 'u' {
						p.i += 2
						if r2, ok := hex4(); ok {
							if dec := utf16.DecodeRune(r, r2); dec != utf8.RuneError {
								out = append(out, dec)
								continue
							}
						}
					}
					p.i = save
					r = utf8.RuneError
				}
				out = append(out, r)
			default:
				return "", false
			}
		default:
			r, size := utf8.DecodeRune(p.s[p.i:])
			p.i += size
			out = append(out, r)
		}
	}
	return "", false
}

func (v *refJSON) get(key string) (*refJSON, bool) {
	for i, k := range v.keys {
		if k == key {
			return v.vals[i], true
		}
	}
	return nil, false
}

func refStrings(v *refJSON) ([]string, bool) {
	if v.kind != 'a' {
		return nil, false
	}
	out := []string{}
	for _, e := range v.elems {
		if e.kind != 's' {
			return nil, false
		}
		out = append(out, e.str)
	}
	return out, true
}

func refUnique(list []string) bool {
	seen := map[string]bool{}
	for _, s := range list {
		if seen[s] {
			return false
		}
		seen[s] = true
	}
	return true
}

func refKeysUnique(v *refJSON) bool {
	switch v.kind {
	case 'o':
		if !refUnique(v.keys) {
			return false
		}
		for _, c := range v.vals {
			if !refKeysUnique(c) {
				return false
			}
		}
	case 'a':
		for _, c := range v.elems {
			if !refKeysUnique(c) {
				return false
			}
		}
	}
	return true
}

func refOnlyKeys(v *refJSON, allowed ...string) bool {
	for _, k := range v.keys {
		found := false
		for _, a := range allowed {
			found = found || k == a
		}
		if !found {
			return false
		}
	}
	return true
}

// refAcceptPolicy implements design section 5 on a JSON document and returns
// the resulting reference policy.
func refAcceptPolicy(data []byte) (refPolicy, bool) {
	var rp refPolicy
	doc, ok := refParseJSON(data)
	if !ok || doc.kind != 'o' || !refKeysUnique(doc) {
		return rp, false
	}
	if !refOnlyKeys(doc, "schemaVersion", "app", "policyRevision", "trustedIssuers", "identityPrefix", "identities", "disabledIdentities", "blockedFingerprints", "constraints", "stripHeaders", "forwardIdentityHeader") {
		return rp, false
	}
	str := func(key string) (string, bool) {
		v, ok := doc.get(key)
		if !ok {
			return "", true
		}
		return v.str, v.kind == 's'
	}
	list := func(key string) ([]string, bool) {
		v, ok := doc.get(key)
		if !ok {
			return nil, true
		}
		return refStrings(v)
	}
	if v, ok := doc.get("schemaVersion"); !ok || v.kind != 'n' || v.num != "1" {
		return rp, false
	}
	app, ok1 := str("app")
	_, ok2 := str("policyRevision")
	prefix, ok3 := str("identityPrefix")
	header, ok4 := str("forwardIdentityHeader")
	issuers, ok5 := list("trustedIssuers")
	ids, ok6 := list("identities")
	disabled, ok7 := list("disabledIdentities")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || strings.TrimSpace(app) == "" || !refPrefix(prefix) || !refForwardHeader(header) {
		return rp, false
	}
	if v, ok := doc.get("stripHeaders"); ok && v.kind != 't' {
		return rp, false
	}
	if len(issuers) == 0 || !refUnique(issuers) || !refUnique(ids) || !refUnique(disabled) {
		return rp, false
	}
	rp = refPolicy{prefix: prefix, trusted: map[string]bool{}, identities: map[string]bool{}, disabled: map[string]bool{}, blocked: map[string]bool{}, constraints: map[string]constraint{}}
	for _, fp := range issuers {
		if !refHexFingerprint(fp) {
			return rp, false
		}
		rp.trusted[fp] = true
	}
	for _, id := range ids {
		if !refIdentity(id, prefix) {
			return rp, false
		}
		rp.identities[id] = true
	}
	for _, id := range disabled {
		if !refIdentity(id, prefix) {
			return rp, false
		}
		rp.disabled[id] = true
	}
	if v, ok := doc.get("blockedFingerprints"); ok {
		if v.kind != 'a' {
			return rp, false
		}
		for _, e := range v.elems {
			if e.kind != 'o' || !refOnlyKeys(e, "fingerprint", "note", "expires") {
				return rp, false
			}
			for _, val := range e.vals {
				if val.kind != 's' {
					return rp, false
				}
			}
			fp, _ := e.get("fingerprint")
			if fp == nil || !refHexFingerprint(fp.str) || rp.blocked[fp.str] {
				return rp, false
			}
			if exp, ok := e.get("expires"); ok && exp.str != "" && !refDate(exp.str) {
				return rp, false
			}
			rp.blocked[fp.str] = true
		}
	}
	if v, ok := doc.get("constraints"); ok {
		if v.kind != 'o' {
			return rp, false
		}
		for i, id := range v.keys {
			rule := v.vals[i]
			if rule.kind != 'o' || !refOnlyKeys(rule, "methods", "paths") || !refIdentity(id, prefix) || !rp.identities[id] {
				return rp, false
			}
			mv, _ := rule.get("methods")
			pv, _ := rule.get("paths")
			if mv == nil || pv == nil {
				return rp, false
			}
			methods, ok1 := refStrings(mv)
			paths, ok2 := refStrings(pv)
			if !ok1 || !ok2 || len(methods) == 0 || len(paths) == 0 || !refUnique(methods) || !refUnique(paths) {
				return rp, false
			}
			for _, m := range methods {
				known := false
				for _, k := range refMethods {
					known = known || m == k
				}
				if !known {
					return rp, false
				}
			}
			for _, path := range paths {
				if !refConstraintPath(path) {
					return rp, false
				}
			}
			rp.constraints[id] = constraint{Methods: methods, Paths: paths}
		}
	}
	return rp, true
}

// refPolicyFromParsed converts an accepted production policy for oracles
// whose subject is not policy parsing itself.
func refPolicyFromParsed(p policy) refPolicy {
	set := func(list []string) map[string]bool {
		m := map[string]bool{}
		for _, s := range list {
			m[s] = true
		}
		return m
	}
	rp := refPolicy{prefix: p.IdentityPrefix, trusted: set(p.TrustedIssuers), identities: set(p.Identities), disabled: set(p.DisabledIdentities), blocked: map[string]bool{}, constraints: map[string]constraint{}}
	for _, b := range p.BlockedFingerprints {
		rp.blocked[b.Fingerprint] = true
	}
	for k, v := range p.Constraints {
		rp.constraints[k] = v
	}
	return rp
}

// Shared fixtures for certificate-based targets.
var fuzzRootRaw = []byte("fuzz-root")

func fuzzCert(raw []byte) *x509.Certificate {
	return &x509.Certificate{Raw: raw, NotBefore: testNow.Add(-time.Hour), NotAfter: testNow.Add(time.Hour)}
}
