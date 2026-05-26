package rules

import "strings"

// goPQC recognizes post-quantum packages by import path: Go's stdlib crypto/mlkem
// and Cloudflare CIRCL (…/kem/kyber, …/sign/dilithium, …).
func goPQC(importPath string) []Match {
	switch {
	case importPath == "crypto/mlkem" || strings.Contains(importPath, "/mlkem"):
		return EvalPQC("ML-KEM")
	case strings.Contains(importPath, "kyber"):
		return EvalPQC("Kyber")
	case strings.Contains(importPath, "dilithium") || strings.Contains(importPath, "/mldsa"):
		return EvalPQC("ML-DSA")
	case strings.Contains(importPath, "sphincs") || strings.Contains(importPath, "/slhdsa"):
		return EvalPQC("SLH-DSA")
	case strings.Contains(importPath, "falcon"):
		return EvalPQC("Falcon")
	}
	return nil
}

// GoEvaluate maps a recognized Go standard-library crypto call to matches. The
// analyzer resolves the import so we get the real package path (e.g. "crypto/md5"),
// which makes detection precise: a call only matches if its selector resolves to a
// known crypto package. Rule identities are shared with the other analyzers.
//
// Note: Go's standard library deliberately omits ECB mode, so there is no ECB
// misuse rule here.
func GoEvaluate(importPath, fn string) []Match {
	if m := goPQC(importPath); len(m) > 0 {
		return m
	}
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
		case "EncryptPKCS1v15", "DecryptPKCS1v15":
			// PKCS#1 v1.5 *encryption* padding is Bleichenbacher-vulnerable.
			return append(evalCipher("RSA"), rsaPKCS1v15Misuse("rsa."+fn))
		case "EncryptOAEP", "DecryptOAEP":
			return evalCipher("RSA")
		case "SignPKCS1v15", "VerifyPKCS1v15", "SignPSS", "VerifyPSS":
			// PKCS#1 v1.5 *signatures* are standard; not a padding-oracle risk.
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

	// --- inventory: strong/neutral assets (positive, info-severity) ---
	case "crypto/rand": // CSPRNG
		switch fn {
		case "Read", "Int", "Prime", "Reader":
			return []Match{CSPRNGAsset("crypto/rand", "crypto/rand."+fn)}
		}
	case "crypto/aes":
		if fn == "NewCipher" {
			return []Match{invCipher("AES", "aes.NewCipher", "")}
		}
	case "golang.org/x/crypto/chacha20poly1305":
		if strings.HasPrefix(fn, "New") {
			return []Match{invCipher("ChaCha20-Poly1305", "chacha20poly1305."+fn, "")}
		}
	case "crypto/hmac":
		if fn == "New" {
			return []Match{macAsset("HMAC", "hmac.New")}
		}
	case "golang.org/x/crypto/pbkdf2":
		if fn == "Key" {
			return []Match{kdfAsset("PBKDF2", "pbkdf2.Key")}
		}
	case "golang.org/x/crypto/hkdf":
		return []Match{kdfAsset("HKDF", "hkdf."+fn)}
	case "golang.org/x/crypto/scrypt":
		if fn == "Key" {
			return []Match{kdfAsset("scrypt", "scrypt.Key")}
		}
	case "golang.org/x/crypto/bcrypt":
		switch fn {
		case "GenerateFromPassword", "CompareHashAndPassword":
			return []Match{kdfAsset("bcrypt", "bcrypt."+fn)}
		}
	case "golang.org/x/crypto/argon2":
		switch fn {
		case "IDKey", "Key":
			return []Match{kdfAsset("Argon2", "argon2."+fn)}
		}
	}
	return nil
}
