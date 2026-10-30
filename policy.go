package traefik_mtls_authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type policy struct {
	SchemaVersion         int                   `json:"schemaVersion"`
	App                   string                `json:"app"`
	PolicyRevision        string                `json:"policyRevision"`
	TrustedIssuers        []string              `json:"trustedIssuers"`
	IdentityPrefix        string                `json:"identityPrefix"`
	Identities            []string              `json:"identities"`
	DisabledIdentities    []string              `json:"disabledIdentities"`
	BlockedFingerprints   []blockedFingerprint  `json:"blockedFingerprints"`
	Constraints           map[string]constraint `json:"constraints"`
	StripHeaders          *bool                 `json:"stripHeaders"`
	ForwardIdentityHeader string                `json:"forwardIdentityHeader"`
}

type blockedFingerprint struct {
	Fingerprint string `json:"fingerprint"`
	Note        string `json:"note"`
	Expires     string `json:"expires"`
}

type constraint struct {
	Methods []string `json:"methods"`
	Paths   []string `json:"paths"`
}

var identityPattern = regexp.MustCompile(`^urn:noqer:mtls:[a-z0-9]+(-[a-z0-9]+)*:[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
var fingerprintPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validIdentity(identity, prefix string) bool {
	return len(identity) <= 128 && strings.HasPrefix(identity, prefix) && identityPattern.MatchString(identity)
}

func parsePolicy(cfg *map[string]interface{}) (policy, error) {
	var p policy
	if cfg == nil || len(*cfg) != 1 {
		return p, fmt.Errorf("plugin config must contain exactly one key: policy or policyJSON")
	}

	var data []byte
	if rawJSON, exists := (*cfg)["policyJSON"]; exists {
		text, ok := rawJSON.(string)
		if !ok {
			return p, fmt.Errorf("policyJSON must be a JSON object encoded as a string")
		}
		data = []byte(text)
	} else {
		raw, ok := (*cfg)["policy"].(map[string]interface{})
		if !ok || raw == nil {
			return p, fmt.Errorf("policy must be an object")
		}
		var err error
		data, err = json.Marshal(raw)
		if err != nil {
			return p, fmt.Errorf("policy must be JSON-compatible: %w", err)
		}
	}
	if err := validateJSON(data); err != nil {
		return p, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, fmt.Errorf("invalid policy: %w", err)
	}
	// JSON accepts null scalars and case-insensitive field names; close both gaps.
	var shape map[string]interface{}
	if err := json.Unmarshal(data, &shape); err != nil {
		return p, err
	}
	if err := checkShape(shape, "policy"); err != nil {
		return p, err
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	return p, nil
}

func checkShape(obj map[string]interface{}, kind string) error {
	for key, value := range obj {
		if value == nil {
			return fmt.Errorf("%s.%s must not be null", kind, key)
		}
		fieldKind := ""
		switch kind {
		case "policy":
			switch key {
			case "schemaVersion":
				fieldKind = "number"
			case "app", "policyRevision", "identityPrefix", "forwardIdentityHeader":
				fieldKind = "string"
			case "trustedIssuers", "identities", "disabledIdentities":
				fieldKind = "strings"
			case "stripHeaders":
				fieldKind = "bool"
			case "constraints":
				fieldKind = "constraints"
			case "blockedFingerprints":
				fieldKind = "blocked"
			}
		case "constraint":
			if key == "methods" || key == "paths" {
				fieldKind = "strings"
			}
		case "blockedFingerprint":
			if key == "fingerprint" || key == "note" || key == "expires" {
				fieldKind = "string"
			}
		}
		valid := false
		switch fieldKind {
		case "number":
			_, valid = value.(float64)
		case "string":
			_, valid = value.(string)
		case "bool":
			_, valid = value.(bool)
		case "strings", "blocked":
			list, ok := value.([]interface{})
			valid = ok
			for _, entry := range list {
				if fieldKind == "strings" {
					if _, ok := entry.(string); !ok {
						valid = false
					}
				} else {
					obj, ok := entry.(map[string]interface{})
					if !ok {
						valid = false
					} else if err := checkShape(obj, "blockedFingerprint"); err != nil {
						return err
					}
				}
			}
		case "constraints":
			mapping, ok := value.(map[string]interface{})
			valid = ok
			for _, entry := range mapping {
				obj, ok := entry.(map[string]interface{})
				if !ok {
					valid = false
				} else if err := checkShape(obj, "constraint"); err != nil {
					return err
				}
			}
		}
		if !valid {
			return fmt.Errorf("unknown field or invalid type: %s.%s", kind, key)
		}
	}
	return nil
}

func (p policy) validate() error {
	if p.SchemaVersion != 1 || strings.TrimSpace(p.App) == "" {
		return fmt.Errorf("schemaVersion must be 1 and app must be non-empty")
	}
	if !strings.HasSuffix(p.IdentityPrefix, ":") || !validIdentity(p.IdentityPrefix+"x", p.IdentityPrefix) {
		return fmt.Errorf("identityPrefix must be a full urn:noqer:mtls:<profile>: namespace")
	}
	if len(p.TrustedIssuers) == 0 {
		return fmt.Errorf("trustedIssuers must not be empty")
	}
	if err := unique(p.TrustedIssuers, "trustedIssuers"); err != nil {
		return err
	}
	for _, fp := range p.TrustedIssuers {
		if !fingerprintPattern.MatchString(fp) {
			return fmt.Errorf("invalid trusted issuer fingerprint")
		}
	}
	for _, list := range [][]string{p.Identities, p.DisabledIdentities} {
		if err := unique(list, "identity list"); err != nil {
			return err
		}
		for _, identity := range list {
			if !validIdentity(identity, p.IdentityPrefix) {
				return fmt.Errorf("invalid identity or identity outside identityPrefix")
			}
		}
	}
	seen := make(map[string]bool)
	for _, entry := range p.BlockedFingerprints {
		if !fingerprintPattern.MatchString(entry.Fingerprint) || seen[entry.Fingerprint] {
			return fmt.Errorf("invalid or duplicate blocked fingerprint")
		}
		seen[entry.Fingerprint] = true
		if entry.Expires != "" {
			if _, err := time.Parse("2006-01-02", entry.Expires); err != nil {
				return fmt.Errorf("blocked fingerprint expires must be YYYY-MM-DD")
			}
		}
	}
	for identity, rule := range p.Constraints {
		if !validIdentity(identity, p.IdentityPrefix) {
			return fmt.Errorf("invalid constraint identity or identity outside identityPrefix")
		}
		if !contains(p.Identities, identity) {
			return fmt.Errorf("constraint key must be an enrolled identity")
		}
		if len(rule.Methods) == 0 || len(rule.Paths) == 0 {
			return fmt.Errorf("constraints require non-empty methods and paths")
		}
		if err := unique(rule.Methods, "constraint methods"); err != nil {
			return err
		}
		if err := unique(rule.Paths, "constraint paths"); err != nil {
			return err
		}
		for _, method := range rule.Methods {
			if !contains([]string{"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}, method) {
				return fmt.Errorf("constraint methods must be uppercase standard HTTP methods")
			}
		}
		for _, path := range rule.Paths {
			u, err := url.ParseRequestURI(path)
			if err != nil || !strings.HasPrefix(path, "/") || (path != "/" && strings.HasSuffix(path, "/")) || strings.Contains(path, "//") || strings.Contains(path, "..") || strings.ContainsAny(path, "?#\\") || u.Path != path || u.EscapedPath() != path {
				return fmt.Errorf("constraint paths must be absolute exact decoded paths without trailing slash, // or ..")
			}
		}
	}
	if p.StripHeaders != nil && !*p.StripHeaders {
		return fmt.Errorf("stripHeaders cannot be false")
	}
	if p.ForwardIdentityHeader != "" && (!validHeader(p.ForwardIdentityHeader) || !strings.HasPrefix(strings.ToLower(p.ForwardIdentityHeader), "x-mtls-") || len(p.ForwardIdentityHeader) <= len("X-Mtls-")) {
		return fmt.Errorf("forwardIdentityHeader must be a valid X-Mtls-* header token with a non-empty suffix")
	}
	return nil
}

func unique(values []string, name string) error {
	seen := make(map[string]bool)
	for _, value := range values {
		if seen[value] {
			return fmt.Errorf("duplicate in %s", name)
		}
		seen[value] = true
	}
	return nil
}

func validHeader(name string) bool {
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", char) {
			continue
		}
		return false
	}
	return name != ""
}
