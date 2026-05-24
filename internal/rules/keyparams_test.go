package rules

import "testing"

func find(ms []Match, ruleID string) (Match, bool) {
	for _, m := range ms {
		if m.RuleID == ruleID {
			return m, true
		}
	}
	return Match{}, false
}

func TestAnnotateKeyRSA(t *testing.T) {
	base := Evaluate("KeyPairGenerator", "RSA") // [CB-ASYM-RSA-KEYGEN]

	// Strong key: enriched, no extra weak finding.
	got := AnnotateKey(base, 2048, "")
	if len(got) != 1 {
		t.Fatalf("RSA-2048: got %d matches, want 1 (%s)", len(got), ruleIDs(got))
	}
	m := got[0]
	if m.KeySize != 2048 || m.ClassicalBits != 112 {
		t.Errorf("RSA-2048: KeySize=%d ClassicalBits=%d, want 2048/112", m.KeySize, m.ClassicalBits)
	}

	// Weak key: enriched keygen finding PLUS a weak-keysize finding.
	got = AnnotateKey(base, 1024, "")
	if len(got) != 2 {
		t.Fatalf("RSA-1024: got %d matches, want 2 (%s)", len(got), ruleIDs(got))
	}
	w, ok := find(got, "CB-WEAK-KEYSIZE")
	if !ok {
		t.Fatalf("RSA-1024: missing CB-WEAK-KEYSIZE (got %s)", ruleIDs(got))
	}
	if w.Severity != SeverityHigh || w.KeySize != 1024 {
		t.Errorf("RSA-1024 weak finding: severity=%s keysize=%d, want high/1024", w.Severity, w.KeySize)
	}
	// The original keygen rule keeps its identity and severity.
	if k, ok := find(got, "CB-ASYM-RSA-KEYGEN"); !ok || k.Severity != SeverityHigh {
		t.Errorf("RSA-1024: keygen finding changed unexpectedly")
	}
}

func TestAnnotateKeyCurve(t *testing.T) {
	base := Evaluate("KeyPairGenerator", "EC") // [CB-ASYM-EC-KEYGEN]

	got := AnnotateKey(base, 0, "SECP256R1")
	if len(got) != 1 {
		t.Fatalf("P-256: got %d matches, want 1 (%s)", len(got), ruleIDs(got))
	}
	if got[0].Curve != "P-256" || got[0].ClassicalBits != 128 {
		t.Errorf("P-256: curve=%q bits=%d, want P-256/128", got[0].Curve, got[0].ClassicalBits)
	}

	got = AnnotateKey(base, 0, "SECP192R1")
	if _, ok := find(got, "CB-WEAK-CURVE"); !ok {
		t.Errorf("P-192: expected CB-WEAK-CURVE (got %s)", ruleIDs(got))
	}
}

func TestAnnotateKeyIgnoresNonAsym(t *testing.T) {
	base := Evaluate("MessageDigest", "MD5") // hash; key size is meaningless
	got := AnnotateKey(base, 1024, "")
	if len(got) != 1 || got[0].KeySize != 0 {
		t.Errorf("hash should be untouched by AnnotateKey, got %s keysize=%d", ruleIDs(got), got[0].KeySize)
	}
}
