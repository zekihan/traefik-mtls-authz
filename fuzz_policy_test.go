package traefik_mtls_authz

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func seedPolicyDocs() []string {
	fp := strings.Repeat("ab", 32)
	good := `{"schemaVersion":1,"app":"test","policyRevision":"rev-1","trustedIssuers":["` + fp + `"],"identityPrefix":"urn:noqer:mtls:clients:","identities":["urn:noqer:mtls:clients:alice"]}`
	full := `{"schemaVersion":1,"app":"journald-upload","policyRevision":"1-3f9c2a1b","trustedIssuers":["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],"identityPrefix":"urn:noqer:mtls:clients:","identities":["urn:noqer:mtls:clients:oci-micro-1","urn:noqer:mtls:clients:z-mac"],"disabledIdentities":["urn:noqer:mtls:clients:z-arch"],"blockedFingerprints":[{"fingerprint":"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210","note":"lost","expires":"2027-10-28"}],"constraints":{"urn:noqer:mtls:clients:oci-micro-1":{"methods":["POST"],"paths":["/insert/journald/upload"]}},"stripHeaders":true,"forwardIdentityHeader":"X-Mtls-Identity"}`
	return []string{
		good, full,
		strings.Replace(good, `"app":"test"`, `"app":"test","app":"other"`, 1),
		strings.Replace(good, `"app":"test"`, `"app":"test","app":"other"`, 1),
		strings.Replace(good, `"app":"test"`, `"App":"other"`, 1),
		strings.Replace(good, `"schemaVersion":1`, `"ſchemaVersion":1`, 1),
		strings.Replace(good, `"schemaVersion":1`, `"schemaVersion":1.0`, 1),
		strings.Replace(good, `"schemaVersion":1`, `"schemaVersion":1e0`, 1),
		strings.Replace(good, `"schemaVersion":1`, `"schemaVersion":"1"`, 1),
		strings.Replace(good, `"app":"test"`, `"app":null`, 1),
		strings.Replace(good, `"app":"test"`, `"app":"  "`, 1),
		strings.Replace(good, `clients:alice"]`, `clients:alice","urn:noqer:mtls:clients:alice"]`, 1),
		strings.Replace(good, `clients:alice"]`, `clients:ALICE"]`, 1),
		strings.Replace(good, `clients:alice"]`, `clients:alıce"]`, 1),
		strings.Replace(good, `"urn:noqer:mtls:clients:"`, `"urn:noqer:mtls:"`, 1),
		strings.Replace(good, `"urn:noqer:mtls:clients:"`, `"urn:noqer:mtls:clients:alice:"`, 1),
		strings.Replace(good, fp, strings.ToUpper(fp), 1),
		strings.Replace(full, `"paths":["/insert/journald/upload"]`, `"paths":["/insert/journald/upload","/insert%2fjournald"]`, 1),
		strings.Replace(full, `"paths":["/insert/journald/upload"]`, `"paths":["/a[b]"]`, 1),
		strings.Replace(full, `"methods":["POST"]`, `"methods":["POST"],"Methods":["GET"]`, 1),
		strings.Replace(full, `"X-Mtls-Identity"`, `"X_Mtls_Identity"`, 1),
		strings.Replace(full, `"2027-10-28"`, `"2027-02-29"`, 1),
		good + " ", good + "{}", "\ufeff" + good,
		`{"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40) + `}`,
	}
}

// FuzzPolicyJSON differential-tests the policyJSON transport against an
// independent strict JSON reader and semantic validator (refAcceptPolicy).
// Properties:
//   - plugin acceptance == reference acceptance (no malformed policy accepted,
//     no valid policy rejected);
//   - an accepted policy agrees field-for-field with the reference;
//   - an accepted policy round-trips through a canonical serialization;
//   - the native "policy" transport decides the same as "policyJSON" for the
//     same JSON document.
func FuzzPolicyJSON(f *testing.F) {
	quietFuzzLogs(f)
	for _, s := range seedPolicyDocs() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		p, err := parsePolicy(&map[string]interface{}{"policyJSON": doc})
		rp, refOK := refAcceptPolicy([]byte(doc))
		if (err == nil) != refOK {
			t.Fatalf("plugin accepted=%v reference accepted=%v err=%v", err == nil, refOK, err)
		}
		if err != nil {
			checkNativeTransport(t, doc, false)
			return
		}
		got := refPolicyFromParsed(p)
		if !reflect.DeepEqual(got, rp) {
			t.Fatalf("decoded policy differs from reference:\nplugin=%#v\nref=%#v", got, rp)
		}
		canonical := canonicalPolicyJSON(t, p)
		again, err := parsePolicy(&map[string]interface{}{"policyJSON": canonical})
		if err != nil {
			t.Fatalf("canonical re-serialization rejected: %v\n%s", err, canonical)
		}
		if !reflect.DeepEqual(normalizePolicy(p), normalizePolicy(again)) {
			t.Fatalf("round trip changed policy:\n%#v\n%#v", p, again)
		}
		checkNativeTransport(t, doc, true)
	})
}

// checkNativeTransport decodes the document the way a provider that preserves
// JSON types would hand it to the plugin and requires the same decision.
func checkNativeTransport(t *testing.T, doc string, want bool) {
	t.Helper()
	var obj map[string]interface{}
	if json.Unmarshal([]byte(doc), &obj) != nil || obj == nil {
		return
	}
	_, err := parsePolicy(&map[string]interface{}{"policy": obj})
	if (err == nil) != want {
		// Documented divergences (docs/fuzzing.md): the native transport
		// receives an already-decoded map, so it cannot see duplicate keys
		// (the last one won) or the number spelling (1.0 and 1e0 became the
		// integer 1). Every other difference is a finding.
		if !want && err == nil && (schemaVersionSpelling(doc) || hasDuplicateKeys(doc)) {
			return
		}
		t.Fatalf("native policy transport accepted=%v but policyJSON accepted=%v (err=%v)", err == nil, want, err)
	}
}

func hasDuplicateKeys(doc string) bool {
	root, ok := refParseJSON([]byte(doc))
	return ok && !refKeysUnique(root)
}

func schemaVersionSpelling(doc string) bool {
	root, ok := refParseJSON([]byte(doc))
	if !ok || root.kind != 'o' {
		return false
	}
	v, ok := root.get("schemaVersion")
	return ok && v.kind == 'n' && v.num != "1"
}

func normalizePolicy(p policy) policy {
	clean := func(list []string) []string {
		if len(list) == 0 {
			return nil
		}
		return list
	}
	p.TrustedIssuers, p.Identities, p.DisabledIdentities = clean(p.TrustedIssuers), clean(p.Identities), clean(p.DisabledIdentities)
	if len(p.BlockedFingerprints) == 0 {
		p.BlockedFingerprints = nil
	}
	if len(p.Constraints) == 0 {
		p.Constraints = nil
	}
	p.StripHeaders = nil
	return p
}

func canonicalPolicyJSON(t *testing.T, p policy) string {
	t.Helper()
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		t.Fatal(err)
	}
	for k, v := range obj {
		if v == nil {
			delete(obj, k)
		}
	}
	out, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// FuzzPolicyFields mutates one field at a time inside an otherwise valid
// policy. Building the document with json.Marshal keeps the JSON valid so the
// fuzzer spends its time on the semantic validators (identity regex, prefix,
// fingerprints, dates, methods, constraint paths and forwarded header).
func FuzzPolicyFields(f *testing.F) {
	quietFuzzLogs(f)
	f.Add("urn:noqer:mtls:clients:", "urn:noqer:mtls:clients:alice", strings.Repeat("a", 64), "2027-01-31", "POST", "/insert/journald/upload", "X-Mtls-Identity", "app")
	f.Add("urn:noqer:mtls:a-b:", "urn:noqer:mtls:a-b:x--y", strings.Repeat("0", 64), "2024-02-29", "GET", "/", "x-mtls-x", " ")
	f.Add("urn:noqer:mtls:clients:", "urn:noqer:mtls:clients:ALICE", strings.Repeat("A", 64), "2023-02-29", "get", "/a/../b", "X-Mtls-", "\t")
	f.Add("URN:noqer:mtls:clients:", "urn:noqer:mtls:clients:alice\n", strings.Repeat("g", 64), "2027-1-31", "CUSTOM", "/a%2fb", "X-Mtls-A\r\nB", " ")
	f.Add("urn:noqer:mtls::", "urn:noqer:mtls:clients:-a", "", "", "PATCH", "/a[b]", "X-Mtls-ſ", "x")
	f.Add("urn:noqer:mtls:clients:", "urn:noqer:mtls:clients:"+strings.Repeat("a", 105), strings.Repeat("f", 63), "0000-02-29", "TRACE", "/a;b=c!$&'()*+,:@~", "", "ok")
	f.Fuzz(func(t *testing.T, prefix, identity, fp, expires, method, path, header, app string) {
		pol := map[string]interface{}{
			"schemaVersion": 1, "app": app, "trustedIssuers": []string{fp},
			"identityPrefix": prefix, "identities": []string{identity},
			"disabledIdentities":    []string{},
			"blockedFingerprints":   []map[string]string{{"fingerprint": fp, "expires": expires}},
			"constraints":           map[string]interface{}{identity: map[string][]string{"methods": {method}, "paths": {path}}},
			"forwardIdentityHeader": header,
		}
		data, err := json.Marshal(pol)
		if err != nil {
			t.Skip()
		}
		doc := string(data)
		_, err = parsePolicy(&map[string]interface{}{"policyJSON": doc})
		_, refOK := refAcceptPolicy(data)
		if (err == nil) != refOK {
			t.Fatalf("plugin accepted=%v reference accepted=%v err=%v\n%s", err == nil, refOK, err, doc)
		}
		// Also check each validator in isolation, so a rejection by one field
		// cannot mask a disagreement in another.
		if got, want := validIdentity(identity, prefix), refIdentity(identity, prefix); got != want {
			t.Fatalf("validIdentity(%q,%q)=%v reference=%v", identity, prefix, got, want)
		}
		if got, want := fingerprintPattern.MatchString(fp), refHexFingerprint(fp); got != want {
			t.Fatalf("fingerprint %q plugin=%v reference=%v", fp, got, want)
		}
		if got, want := checkPathAlone(path), refConstraintPath(path); got != want {
			t.Fatalf("constraint path %q plugin=%v reference=%v", path, got, want)
		}
		if got, want := checkHeaderAlone(header), refForwardHeader(header); got != want {
			t.Fatalf("forward header %q plugin=%v reference=%v", header, got, want)
		}
		if got, want := checkPrefixAlone(prefix), refPrefix(prefix); got != want {
			t.Fatalf("identityPrefix %q plugin=%v reference=%v", prefix, got, want)
		}
		if got, want := checkExpiresAlone(expires), expires == "" || refDate(expires); got != want {
			t.Fatalf("expires %q plugin=%v reference=%v", expires, got, want)
		}
	})
}

func baseFieldPolicy() policy {
	tr := true
	return policy{SchemaVersion: 1, App: "app", TrustedIssuers: []string{strings.Repeat("a", 64)}, IdentityPrefix: "urn:noqer:mtls:clients:", Identities: []string{testIdentity}, StripHeaders: &tr}
}

func checkPathAlone(path string) bool {
	p := baseFieldPolicy()
	p.Constraints = map[string]constraint{testIdentity: {Methods: []string{"GET"}, Paths: []string{path}}}
	return p.validate() == nil
}

func checkHeaderAlone(header string) bool {
	p := baseFieldPolicy()
	p.ForwardIdentityHeader = header
	return p.validate() == nil
}

func checkPrefixAlone(prefix string) bool {
	p := baseFieldPolicy()
	p.IdentityPrefix, p.Identities = prefix, nil
	return p.validate() == nil
}

func checkExpiresAlone(expires string) bool {
	p := baseFieldPolicy()
	p.BlockedFingerprints = []blockedFingerprint{{Fingerprint: strings.Repeat("b", 64), Expires: expires}}
	return p.validate() == nil
}
