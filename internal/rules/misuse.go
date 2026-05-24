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

// WeakPRNG is the misuse match for key/IV material drawn from a non-cryptographic
// PRNG (e.g. java.util.Random). algo is the cipher when known, otherwise "".
func WeakPRNG(algo string) Match {
	if algo == "" {
		algo = "key/IV material"
	}
	return Match{
		RuleID:      "CB-MISUSE-WEAK-PRNG",
		Title:       "Key/IV material from a non-cryptographic PRNG",
		Severity:    SeverityHigh,
		Category:    CategoryMisuse,
		Algorithm:   algo,
		Detail:      "non-CSPRNG source",
		Remediation: "Use a cryptographically secure RNG (SecureRandom in Java/Kotlin, crypto/rand in Go, secrets/os.urandom in Python, RandomNumberGenerator in .NET) for key and IV material.",
	}
}

// TimingCompare is the misuse match for comparing a MAC or digest with a
// variable-time comparison (a timing side-channel).
func TimingCompare() Match {
	return Match{
		RuleID:      "CB-MISUSE-TIMING-COMPARE",
		Title:       "Non-constant-time comparison of a MAC/digest",
		Severity:    SeverityMedium,
		Category:    CategoryMisuse,
		Algorithm:   "MAC",
		Primitive:   "mac",
		Detail:      "variable-time comparison",
		Remediation: "Use a constant-time comparison (MessageDigest.isEqual in Java/Kotlin, hmac.compare_digest in Python, crypto/subtle.ConstantTimeCompare or hmac.Equal in Go, CryptographicOperations.FixedTimeEquals in .NET).",
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
