package rules

import (
	"fmt"
	"strings"
)

// weakClassicalBits is the minimum classical security level (in bits) considered
// adequate today (NIST SP 800-57: 112 bits ~ RSA-2048 / P-224). Below this, a key
// is classically weak regardless of the quantum threat.
const weakClassicalBits = 112

// AnnotateKey enriches asymmetric matches with a detected key size or curve and,
// when the parameters fall below modern classical strength, appends a separate
// weak-parameter finding. bits <= 0 and curve == "" mean "unknown" (no-op).
func AnnotateKey(matches []Match, bits int, curve string) []Match {
	out := make([]Match, 0, len(matches)+1)
	var weak []Match
	for _, m := range matches {
		m = annotate(m, bits, curve)
		out = append(out, m)
		if w, ok := weakParam(m); ok {
			weak = append(weak, w)
		}
	}
	return append(out, weak...)
}

func annotate(m Match, bits int, curve string) Match {
	switch m.Algorithm {
	case "RSA", "DSA", "DH":
		if bits > 0 {
			m.KeySize = bits
			m.ClassicalBits = classicalIFC(bits)
			m.Detail = fmt.Sprintf("%s-%d", m.Algorithm, bits)
		}
	case "EC", "ECDSA":
		if c := normalizeCurve(curve); c != "" {
			m.Curve = c
			m.ClassicalBits = ecClassical(c)
			m.Detail = m.Algorithm + " " + c
		}
	}
	return m
}

// weakParam returns a weak-parameter finding when m carries a classically weak
// key size or curve.
func weakParam(m Match) (Match, bool) {
	if m.ClassicalBits == 0 || m.ClassicalBits >= weakClassicalBits {
		return Match{}, false
	}
	w := Match{
		Severity:      SeverityHigh,
		Category:      CategoryWeak,
		Algorithm:     m.Algorithm,
		Primitive:     m.Primitive,
		KeySize:       m.KeySize,
		Curve:         m.Curve,
		ClassicalBits: m.ClassicalBits,
	}
	if m.KeySize > 0 {
		w.RuleID = "CB-WEAK-KEYSIZE"
		w.Detail = fmt.Sprintf("%s-%d", m.Algorithm, m.KeySize)
		w.Title = fmt.Sprintf("%s-%d is classically weak (~%d-bit security)", m.Algorithm, m.KeySize, m.ClassicalBits)
		w.Remediation = "Use at least 3072-bit keys (128-bit security), or migrate to PQC (ML-KEM / ML-DSA)."
	} else {
		w.RuleID = "CB-WEAK-CURVE"
		w.Detail = m.Algorithm + " " + m.Curve
		w.Title = fmt.Sprintf("Curve %s is classically weak (~%d-bit security)", m.Curve, m.ClassicalBits)
		w.Remediation = "Use at least P-256 (128-bit security), or migrate to PQC."
	}
	return w, true
}

// classicalIFC approximates the classical security level (bits) of an
// integer-factorization / finite-field key of the given size (NIST SP 800-57).
func classicalIFC(bits int) int {
	switch {
	case bits >= 15360:
		return 256
	case bits >= 7680:
		return 192
	case bits >= 3072:
		return 128
	case bits >= 2048:
		return 112
	case bits >= 1024:
		return 80
	case bits > 0:
		return 56
	}
	return 0
}

func ecClassical(curve string) int {
	switch curve {
	case "P-521":
		return 256
	case "P-384":
		return 192
	case "P-256", "secp256k1", "X25519":
		return 128
	case "P-224":
		return 112
	case "P-192":
		return 96
	case "P-160":
		return 80
	}
	return 0
}

// normalizeCurve maps the many spellings of a curve to a canonical name.
func normalizeCurve(c string) string {
	if c == "" {
		return ""
	}
	u := strings.ToUpper(c)
	switch {
	case strings.Contains(u, "25519"):
		return "X25519"
	case strings.Contains(u, "256K1"):
		return "secp256k1"
	case strings.Contains(u, "521"):
		return "P-521"
	case strings.Contains(u, "384"):
		return "P-384"
	case strings.Contains(u, "256"), strings.Contains(u, "PRIME256"):
		return "P-256"
	case strings.Contains(u, "224"):
		return "P-224"
	case strings.Contains(u, "192"):
		return "P-192"
	case strings.Contains(u, "160"):
		return "P-160"
	}
	return c
}
