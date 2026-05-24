package rules

import "strings"

// GoEvaluate maps a recognized Go standard-library crypto call to matches. The
// analyzer resolves the import so we get the real package path (e.g. "crypto/md5"),
// which makes detection precise: a call only matches if its selector resolves to a
// known crypto package. Rule identities are shared with the other analyzers.
//
// Note: Go's standard library deliberately omits ECB mode, so there is no ECB
// misuse rule here.
func GoEvaluate(importPath, fn string) []Match {
	switch importPath {
	// --- hashes ---
	case "crypto/md5":
		if fn == "New" || fn == "Sum" {
			return evalDigest("md5")
		}
	case "crypto/sha1":
		if fn == "New" || fn == "Sum" {
			return evalDigest("sha1")
		}
	case "crypto/sha256":
		if strings.HasPrefix(fn, "New") || strings.HasPrefix(fn, "Sum") {
			return evalDigest("sha256")
		}
	case "crypto/sha512":
		if strings.HasPrefix(fn, "New") || strings.HasPrefix(fn, "Sum") {
			return evalDigest("sha512")
		}

	// --- weak symmetric ciphers ---
	case "crypto/des":
		switch fn {
		case "NewCipher":
			return evalCipher("DES")
		case "NewTripleDESCipher":
			return evalCipher("DESede")
		}
	case "crypto/rc4":
		if fn == "NewCipher" {
			return evalCipher("RC4")
		}

	// --- quantum-vulnerable asymmetric crypto ---
	case "crypto/rsa":
		switch fn {
		case "GenerateKey", "GenerateMultiPrimeKey":
			return evalKeyPairGen("RSA")
		case "EncryptPKCS1v15", "DecryptPKCS1v15", "EncryptOAEP", "DecryptOAEP":
			return evalCipher("RSA")
		case "SignPKCS1v15", "VerifyPKCS1v15", "SignPSS", "VerifyPSS":
			return evalSignature("RSA")
		}
	case "crypto/ecdsa":
		switch fn {
		case "GenerateKey":
			return evalKeyPairGen("EC")
		case "Sign", "Verify", "SignASN1", "VerifyASN1":
			return evalSignature("ECDSA")
		}
	case "crypto/ed25519":
		switch fn {
		case "GenerateKey", "NewKeyFromSeed", "Sign", "Verify":
			return []Match{qv("CB-ASYM-ED25519", "Ed25519",
				"Ed25519 signatures are quantum-vulnerable", "signature",
				[]string{"sign", "verify"}, "ed25519."+fn,
				"Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).")}
		}
	case "crypto/dsa":
		switch fn {
		case "GenerateKey", "GenerateParameters", "Sign", "Verify":
			return evalKeyPairGen("DSA")
		}
	case "crypto/ecdh":
		switch fn {
		case "X25519", "P256", "P384", "P521":
			return []Match{qv("CB-KA-ECDH", "ECDH",
				"ECDH key agreement is quantum-vulnerable", "key-agree",
				[]string{"keyderive"}, "ecdh."+fn, "Migrate to ML-KEM (FIPS 203).")}
		}
	}
	return nil
}
