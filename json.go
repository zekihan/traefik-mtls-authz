package traefik_mtls_authz

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"
)

// validateJSON rejects duplicate keys, trailing documents and lossy Unicode decoding.
// The object form is marshaled first and goes through the same checks.
func validateJSON(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("policy JSON must be valid UTF-8")
	}
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
	if !validSurrogateEscapes(data) {
		return fmt.Errorf("policy JSON contains an unpaired Unicode surrogate escape")
	}
	return nil
}

// encoding/json replaces unpaired surrogates with U+FFFD. After checking the JSON
// syntax, inspect the escapes directly to distinguish them from a literal U+FFFD.
func validSurrogateEscapes(data []byte) bool {
	const highStart, lowStart, surrogateEnd = 0xd800, 0xdc00, 0xdfff
	for {
		i := bytes.IndexByte(data, '\\')
		if i == -1 {
			return true
		}
		data = data[i+1:]
		if data[0] != 'u' {
			data = data[1:]
			continue
		}
		unit, _ := strconv.ParseUint(string(data[1:5]), 16, 16)
		data = data[5:]
		if unit < highStart || unit > surrogateEnd {
			continue
		}
		if unit >= lowStart || !bytes.HasPrefix(data, []byte(`\u`)) {
			return false
		}
		low, _ := strconv.ParseUint(string(data[2:6]), 16, 16)
		if low < lowStart || low > surrogateEnd {
			return false
		}
		data = data[6:]
	}
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
