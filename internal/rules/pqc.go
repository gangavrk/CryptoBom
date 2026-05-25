package rules

import "strings"

// EvalPQC recognizes post-quantum algorithm names and inventories them as
// quantum-safe (a positive finding — migration progress, not debt). It matches the
// NIST names and the common pre-standard / library names. Returns nil for anything
// that isn't post-quantum.
func EvalPQC(name string) []Match {
	n := strings.NewReplacer("-", "", "_", "", " ", "", "+", "").Replace(strings.ToUpper(name))
	hybrid := isHybridPQC(n)
	switch {
	case strings.Contains(n, "MLKEM"), strings.Contains(n, "KYBER"):
		return []Match{pqc("ML-KEM", "kem", name, hybrid)}
	case strings.Contains(n, "MLDSA"), strings.Contains(n, "DILITHIUM"):
		return []Match{pqc("ML-DSA", "signature", name, hybrid)}
	case strings.Contains(n, "SLHDSA"), strings.Contains(n, "SPHINCS"):
		return []Match{pqc("SLH-DSA", "signature", name, hybrid)}
	case strings.Contains(n, "FNDSA"), strings.Contains(n, "FALCON"):
		return []Match{pqc("FN-DSA", "signature", name, hybrid)}
	case strings.Contains(n, "HQC"):
		return []Match{pqc("HQC", "kem", name, hybrid)}
	case strings.Contains(n, "FRODO"):
		return []Match{pqc("FrodoKEM", "kem", name, hybrid)}
	case strings.Contains(n, "MCELIECE"):
		return []Match{pqc("Classic-McEliece", "kem", name, hybrid)}
	case strings.Contains(n, "BIKE"):
		return []Match{pqc("BIKE", "kem", name, hybrid)}
	case strings.Contains(n, "XMSS"), strings.Contains(n, "LMS"):
		return []Match{pqc("XMSS/LMS", "signature", name, hybrid)}
	}
	return nil
}

// isHybridPQC reports whether a name combines a classical algorithm with a PQC one
// (e.g. X25519MLKEM768), the recommended transitional posture.
func isHybridPQC(normalized string) bool {
	for _, classical := range []string{"X25519", "X448", "P256", "P384", "P521", "SECP", "ECDH", "RSA"} {
		if strings.Contains(normalized, classical) {
			return true
		}
	}
	return false
}

func pqc(family, primitive, detail string, hybrid bool) Match {
	title := family + " (post-quantum) in use"
	if hybrid {
		title = family + " hybrid (post-quantum) in use"
	}
	return Match{
		RuleID:    "CB-PQC",
		Title:     title,
		Severity:  SeverityInfo,
		Category:  CategoryQuantumSafe,
		Algorithm: family,
		Detail:    detail,
		Primitive: primitive,
	}
}
