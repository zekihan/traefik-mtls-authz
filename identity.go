package traefik_mtls_authz

import (
	"crypto/x509"
	"encoding/asn1"
)

// rawURIIdentity reads the URI's actual IA5 bytes from the SAN extension. x509's
// parsed URIs have already passed through net/url, which lowercases the scheme.
// A valid identity requires exactly one primitive context-specific URI entry and
// no other GeneralName entries. The second result is empty on success or a deny code.
// This is identity extraction only; certificate verification remains Traefik's job.
func rawURIIdentity(leaf *x509.Certificate) (string, string) {
	identity := ""
	extensions, uris, entries := 0, 0, 0
	for _, extension := range leaf.Extensions {
		if !extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		extensions++
		if extensions != 1 {
			return "", "identity_invalid"
		}
		var sequence asn1.RawValue
		rest, err := asn1.Unmarshal(extension.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return "", "identity_invalid"
		}
		names := sequence.Bytes
		for len(names) > 0 {
			var name asn1.RawValue
			rest, err = asn1.Unmarshal(names, &name)
			if err != nil || name.Class != asn1.ClassContextSpecific {
				return "", "identity_invalid"
			}
			// Go ignores several GeneralName alternatives (and even unknown tags).
			// Count every entry, not just the fields exposed by x509.Certificate.
			if name.Tag < 0 || name.Tag > 8 {
				return "", "identity_invalid"
			}
			entries++
			names = rest
			if name.Tag == 6 {
				if name.IsCompound {
					return "", "identity_invalid"
				}
				uris++
				identity = string(name.Bytes)
			}
		}
	}
	if extensions != 1 || uris == 0 {
		return "", "identity_invalid"
	}
	if entries != 1 {
		return "", "identity_ambiguous"
	}
	return identity, ""
}
