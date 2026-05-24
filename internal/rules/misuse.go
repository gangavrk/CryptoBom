package rules

// HardcodedKey is the misuse match for a literal key embedded in source. algo is
// the cipher when known (e.g. "AES"), otherwise "".
func HardcodedKey(algo string) Match {
	if algo == "" {
		algo = "symmetric key"
	}
	return Match{
		RuleID:      "CB-MISUSE-HARDCODED-KEY",
		Title:       "Hardcoded cryptographic key",
		Severity:    SeverityHigh,
		Category:    CategoryMisuse,
		Algorithm:   algo,
		Detail:      "literal key material",
		Remediation: "Load keys from a secrets manager or KMS; never embed key material in source.",
	}
}

// StaticIV is the misuse match for a literal/static IV or nonce. algo is the
// cipher when known, otherwise "".
func StaticIV(algo string) Match {
	if algo == "" {
		algo = "IV"
	}
	return Match{
		RuleID:      "CB-MISUSE-STATIC-IV",
		Title:       "Hardcoded/static initialization vector",
		Severity:    SeverityMedium,
		Category:    CategoryMisuse,
		Algorithm:   algo,
		Detail:      "literal IV/nonce",
		Remediation: "Generate a fresh random IV/nonce for every encryption.",
	}
}
