package traefik_mtls_authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// validateJSON rejects duplicate keys and trailing documents in policyJSON.
// The object form is marshaled first and goes through the same checks.
func validateJSON(data []byte) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return fmt.Errorf("policy must be a JSON object")
	}
	if err := jsonObject(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("policy must contain exactly one JSON document")
	}
	return nil
}

func jsonObject(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("policy nesting exceeds 32 levels")
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("policy object key must be a string")
		}
		if seen[key] {
			return fmt.Errorf("duplicate policy JSON key %q", key)
		}
		seen[key] = true
		if err := jsonValue(d, depth+1); err != nil {
			return err
		}
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('}') {
		return fmt.Errorf("invalid policy JSON object")
	}
	return nil
}

func jsonValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return fmt.Errorf("policy nesting exceeds 32 levels")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case json.Delim('{'):
		return jsonObject(d, depth)
	case json.Delim('['):
		for d.More() {
			if err := jsonValue(d, depth+1); err != nil {
				return err
			}
		}
		token, err = d.Token()
		if err != nil {
			return err
		}
		if token != json.Delim(']') {
			return fmt.Errorf("invalid policy JSON array")
		}
	case json.Delim('}'), json.Delim(']'):
		return fmt.Errorf("unexpected policy JSON delimiter")
	}
	return nil
}
