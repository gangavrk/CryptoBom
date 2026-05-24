// Package material inventories cryptographic material that lives in the repository
// as files — certificates, private/public keys, and keystores — rather than crypto
// API calls in source. Certificates are parsed (crypto/x509) to surface weak
// signatures, quantum-vulnerable / undersized keys, and expiry.
package material

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"strings"
	"time"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze inspects a candidate key/cert file and returns crypto-material findings.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	var out []rules.Finding
	add := func(matches []rules.Match) {
		for _, m := range matches {
			out = append(out, rules.Finding{Match: m, File: path, Line: 1, Column: 1, Evidence: filepath.Base(path)})
		}
	}

	// 1. PEM blocks (the common, unambiguous case).
	pemFound := false
	for rest := src; ; {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		pemFound = true
		add(classifyPEM(block))
		rest = r
	}
	if pemFound {
		return out, nil
	}

	// 2. A bare DER certificate (binary .der / .cer).
	if cert, err := x509.ParseCertificate(src); err == nil {
		add(certMatches(cert))
		return out, nil
	}

	// 3. SSH public key line (ssh-rsa AAAA…, ssh-ed25519 …).
	if isSSHPublicKey(src) {
		add([]rules.Match{rules.PublicKeyFile("SSH")})
		return out, nil
	}

	// 4. Binary keystore by extension (can't parse without extra libs).
	if format := keystoreFormat(path); format != "" {
		add([]rules.Match{rules.KeystoreFile(format)})
	}
	return out, nil
}

func classifyPEM(block *pem.Block) []rules.Match {
	switch {
	case block.Type == "CERTIFICATE":
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return certMatches(cert)
		}
		return []rules.Match{rules.Certificate("", "")}
	case block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY":
		return []rules.Match{rules.PublicKeyFile(labelAlgo(block.Type))}
	case strings.Contains(block.Type, "PRIVATE KEY"):
		return []rules.Match{rules.PrivateKeyFile(labelAlgo(block.Type))}
	}
	return nil
}

func certMatches(cert *x509.Certificate) []rules.Match {
	ms := []rules.Match{rules.Certificate(cert.Subject.CommonName, cert.NotAfter.UTC().Format(time.RFC3339))}
	if hash, sev, ok := weakCertSig(cert.SignatureAlgorithm); ok {
		ms = append(ms, rules.CertWeakSignature(hash, sev))
	}
	if cert.NotAfter.Before(time.Now()) {
		ms = append(ms, rules.CertExpired(cert.NotAfter.UTC().Format("2006-01-02")))
	}
	algo, bits, curve := certKeyParams(cert)
	ms = append(ms, rules.CertKey(algo, bits, curve)...)
	return ms
}

func certKeyParams(cert *x509.Certificate) (algo string, bits int, curve string) {
	switch pk := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pk.N.BitLen(), ""
	case *ecdsa.PublicKey:
		return "EC", 0, pk.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519", 0, ""
	case *dsa.PublicKey:
		return "DSA", 0, ""
	}
	return "", 0, ""
}

// weakCertSig reports whether a certificate signature algorithm uses a broken hash.
func weakCertSig(sa x509.SignatureAlgorithm) (string, rules.Severity, bool) {
	switch sa {
	case x509.MD2WithRSA, x509.MD5WithRSA:
		return "MD5", rules.SeverityHigh, true
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		return "SHA-1", rules.SeverityMedium, true
	}
	return "", "", false
}

// labelAlgo extracts the algorithm from a PEM label ("RSA PRIVATE KEY" -> "RSA").
func labelAlgo(label string) string {
	switch {
	case strings.HasPrefix(label, "RSA"):
		return "RSA"
	case strings.HasPrefix(label, "EC"):
		return "EC"
	case strings.HasPrefix(label, "DSA"):
		return "DSA"
	case strings.HasPrefix(label, "OPENSSH"):
		return "SSH"
	case strings.HasPrefix(label, "PGP"):
		return "PGP"
	}
	return ""
}

func isSSHPublicKey(src []byte) bool {
	s := strings.TrimSpace(string(src))
	for _, p := range []string{"ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-"} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func keystoreFormat(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".p12", ".pfx":
		return "PKCS#12"
	case ".jks", ".keystore":
		return "JKS"
	}
	return ""
}

// IsMaterialFile reports whether a file name looks like cryptographic material.
func IsMaterialFile(name string) bool {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx", ".jks", ".keystore", ".asc", ".gpg", ".pgp":
		return true
	}
	switch name {
	case "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys":
		return true
	}
	return false
}
