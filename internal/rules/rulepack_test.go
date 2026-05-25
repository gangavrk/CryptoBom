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
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := p.validate(); err == nil {
				t.Errorf("validate() = nil, want error for %q", name)
			}
		})
	}
}
