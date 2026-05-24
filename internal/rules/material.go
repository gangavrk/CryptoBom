package rules

import "fmt"

// PrivateKeyFile is the match for a private key found in the repository. algo is
// the key algorithm when known (e.g. "RSA"), otherwise "".
func PrivateKeyFile(algo string) Match {
	name := "private key"
	if algo != "" {
		name = algo + " private key"
	}
	return Match{
		RuleID:       "CB-MATERIAL-PRIVATE-KEY",
		Title:        "Private key committed to the repository",
		Severity:     SeverityHigh,
		Category:     CategoryMisuse,
		Algorithm:    name,
		AssetKind:    "material",
		MaterialType: "private-key",
		Remediation:  "Never commit private keys; store them in a secrets manager/KMS and rotate any that were exposed.",
	}
}

// PublicKeyFile inventories a public key.
func PublicKeyFile(algo string) Match {
	name := "public key"
	if algo != "" {
		name = algo + " public key"
	}
	return Match{
		RuleID:       "CB-INV-PUBLIC-KEY",
		Title:        "Public key in use",
		Severity:     SeverityInfo,
		Category:     CategoryInventory,
		Algorithm:    name,
		AssetKind:    "material",
		MaterialType: "public-key",
	}
}

// Certificate inventories an X.509 certificate.
func Certificate(subject, notAfter string) Match {
	return Match{
		RuleID:       "CB-INV-CERTIFICATE",
		Title:        "X.509 certificate in use",
		Severity:     SeverityInfo,
		Category:     CategoryInventory,
		Algorithm:    "X.509 certificate",
		AssetKind:    "certificate",
		CertSubject:  subject,
		CertNotAfter: notAfter,
	}
}

// CertWeakSignature flags a certificate signed with a weak hash (MD5/SHA-1).
func CertWeakSignature(hash string, sev Severity) Match {
	return Match{
		RuleID:      "CB-WEAK-CERT-SIG",
		Title:       "Certificate signed with " + hash,
		Severity:    sev,
		Category:    CategoryWeak,
		Algorithm:   hash,
		Primitive:   "hash",
		Detail:      "certificate signature",
		Remediation: "Reissue the certificate with a SHA-256 (or stronger) signature.",
	}
}

// CertExpired flags an expired certificate.
func CertExpired(notAfter string) Match {
	return Match{
		RuleID:      "CB-CERT-EXPIRED",
		Title:       "Certificate is expired (notAfter " + notAfter + ")",
		Severity:    SeverityLow,
		Category:    CategoryInventory,
		Algorithm:   "X.509 certificate",
		Detail:      "expired " + notAfter,
		Remediation: "Renew or remove the expired certificate.",
	}
}

// CertKey describes a certificate's public key as a (quantum-vulnerable) algorithm
// asset, annotated with its size/curve. Returns nil for unrecognized key types.
func CertKey(algo string, bits int, curve string) []Match {
	var m Match
	switch algo {
	case "RSA":
		m = Match{RuleID: "CB-CERT-KEY-RSA", Title: "Certificate uses an RSA key (quantum-vulnerable)",
			Severity: SeverityHigh, Category: CategoryQuantumVulnerable, Algorithm: "RSA",
			Primitive: "pke", Functions: []string{"sign", "verify"},
			Remediation: "Plan migration to PQC certificates (ML-DSA / FIPS 204)."}
	case "EC", "ECDSA":
		m = Match{RuleID: "CB-CERT-KEY-EC", Title: "Certificate uses an elliptic-curve key (quantum-vulnerable)",
			Severity: SeverityHigh, Category: CategoryQuantumVulnerable, Algorithm: "EC",
			Primitive: "signature", Functions: []string{"sign", "verify"},
			Remediation: "Plan migration to PQC certificates (ML-DSA / FIPS 204)."}
	case "Ed25519":
		m = qv("CB-CERT-KEY-ED25519", "Ed25519", "Certificate uses an Ed25519 key (quantum-vulnerable)",
			"signature", []string{"sign", "verify"}, "Ed25519",
			"Plan migration to PQC certificates (ML-DSA / FIPS 204).")
	case "DSA":
		m = Match{RuleID: "CB-CERT-KEY-DSA", Title: "Certificate uses a DSA key (quantum-vulnerable and legacy)",
			Severity: SeverityHigh, Category: CategoryQuantumVulnerable, Algorithm: "DSA",
			Primitive: "signature", Functions: []string{"sign", "verify"},
			Remediation: "Plan migration to PQC certificates (ML-DSA / FIPS 204)."}
	default:
		return nil
	}
	return AnnotateKey([]Match{m}, bits, curve)
}

// KeystoreFile flags a binary keystore (PKCS#12 / JKS), which bundles private keys.
func KeystoreFile(format string) Match {
	return Match{
		RuleID:       "CB-MATERIAL-KEYSTORE",
		Title:        fmt.Sprintf("%s keystore committed to the repository", format),
		Severity:     SeverityHigh,
		Category:     CategoryMisuse,
		Algorithm:    format + " keystore",
		AssetKind:    "material",
		MaterialType: "private-key",
		Remediation:  "Keystores bundle private keys; keep them out of source control and rotate exposed keys.",
	}
}
