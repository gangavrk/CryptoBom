package rules

import "testing"

// TestRulepackValidationCatchesErrors proves the loader rejects malformed packs,
// so a bad rulepack.yaml can never ship silently.
func TestRulepackValidationCatchesErrors(t *testing.T) {
	goodRefs := map[string]Reference{
		"r1": {Authority: "NIST", ID: "X", URL: "https://example.com"},
	}
	cases := map[string]rulepack{
		"missing version": {
			References: goodRefs,
		},
		"malformed reference (no https)": {
			Version:    "1",
			References: map[string]Reference{"r1": {Authority: "NIST", ID: "X", URL: "http://x"}},
		},
		"rule with unknown reference": {
			Version:    "1",
			References: goodRefs,
			Rules:      map[string]ruleMeta{"CB-X": {StandardStatus: StatusFinalized, References: []string{"missing"}}},
		},
		"rule with bad status": {
			Version:    "1",
			References: goodRefs,
			Rules:      map[string]ruleMeta{"CB-X": {StandardStatus: "bogus", References: []string{"r1"}}},
		},
		"rule with no references": {
			Version:    "1",
			References: goodRefs,
			Rules:      map[string]ruleMeta{"CB-X": {StandardStatus: StatusFinalized}},
		},
		"profile with unknown reference": {
			Version:    "1",
			References: goodRefs,
			Profiles: map[string]profileDef{"p": {
				Name: "P", Reference: "missing",
				Policy: map[Category]policyEntry{CategoryWeak: {Status: ComplianceViolation}},
			}},
		},
		"profile with bad status": {
			Version:    "1",
			References: goodRefs,
			Profiles: map[string]profileDef{"p": {
				Name: "P", Reference: "r1",
				Policy: map[Category]policyEntry{CategoryWeak: {Status: "bogus"}},
			}},
		},
		"profile with bad severity override": {
			Version:    "1",
			References: goodRefs,
			Profiles: map[string]profileDef{"p": {
				Name: "P", Reference: "r1",
				Policy: map[Category]policyEntry{CategoryWeak: {Status: ComplianceViolation, Severity: "bogus"}},
			}},
		},
		"malformed oid": {
			Version:    "1",
			References: goodRefs,
			OIDs:       map[string]string{"RSA": "1.2.not-numeric.1"},
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := p.validate(); err == nil {
				t.Errorf("validate() = nil, want error for %q", name)
			}
		})
	}
}

func TestOIDFor(t *testing.T) {
	want := map[string]string{
		"RSA":     "1.2.840.113549.1.1.1",
		"EC":      "1.2.840.10045.2.1",
		"ECDSA":   "1.2.840.10045.2.1",
		"Ed25519": "1.3.101.112",
		"MD5":     "1.2.840.113549.2.5",
		"SHA-256": "2.16.840.1.101.3.4.2.1",
	}
	for alg, oid := range want {
		if got := OIDFor(alg); got != oid {
			t.Errorf("OIDFor(%q) = %q, want %q", alg, got, oid)
		}
	}
	// Deliberately unmapped (ambiguous / no algorithm-level OID) -> "".
	for _, alg := range []string{"AES", "DES", "3DES", "EdDSA", "ECDH", "DH", "ML-DSA", "HMAC-MD5", "unknown"} {
		if got := OIDFor(alg); got != "" {
			t.Errorf("OIDFor(%q) = %q, want \"\" (should not be mapped)", alg, got)
		}
	}
	// Every mapped OID is well-formed.
	for alg, oid := range pack.OIDs {
		if !isOID(oid) {
			t.Errorf("oids[%s] = %q is not a valid OID", alg, oid)
		}
	}
}
