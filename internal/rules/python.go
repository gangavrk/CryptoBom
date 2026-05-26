package rules

import "strings"

// PyEvaluate maps a recognized Python crypto call to matches. The analyzer
// extracts the call's qualifier and method so the crypto knowledge stays here:
//
//	obj    qualifying name, e.g. "hashlib", "hashes", "rsa", "AES", "modes", "PKCS1_OAEP"
//	attr   called attribute, e.g. "md5", "new", "SHA1", "ECB", "generate_private_key"
//	strArg first string-literal argument, if any (e.g. hashlib.new("md5"))
//	ecbArg true if a *.MODE_ECB argument was passed (pycryptodome)
//
// It deliberately matches only qualified calls from the two dominant libraries
// (pyca/cryptography and pycryptodome); bare names are left alone to avoid false
// positives. Rule identities are shared with the Java analyzer.
func PyEvaluate(obj, attr, strArg string, ecbArg bool) []Match {
	switch obj {
	// --- post-quantum (liboqs-python): oqs.KeyEncapsulation("Kyber768") ---
	case "oqs":
		return EvalPQC(strArg)

	// --- inventory: CSPRNGs, MACs (positive, info-severity) ---
	case "secrets": // secrets.token_bytes / token_hex / randbits / …
		switch attr {
		case "token_bytes", "token_hex", "token_urlsafe", "randbits", "randbelow", "choice", "SystemRandom":
			return []Match{CSPRNGAsset("secrets", "secrets."+attr)}
		}
	case "os":
		if attr == "urandom" {
			return []Match{CSPRNGAsset("os.urandom", "os.urandom")}
		}
	case "hmac":
		if attr == "new" {
			return []Match{macAsset("HMAC", "hmac.new")}
		}

	// --- hashes & KDFs ---
	case "hashlib":
		switch attr {
		case "new":
			return evalDigest(strArg)
		case "pbkdf2_hmac":
			return []Match{kdfAsset("PBKDF2", "hashlib.pbkdf2_hmac")}
		case "scrypt":
			return []Match{kdfAsset("scrypt", "hashlib.scrypt")}
		}
		return evalDigest(attr) // hashlib.md5()
	case "hashes": // pyca/cryptography: hashes.SHA1()
		return evalDigest(attr)
	case "MD5", "MD2", "MD4", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512":
		if attr == "new" { // pycryptodome: from Crypto.Hash import MD5; MD5.new()
			return evalDigest(obj)
		}

	// --- cipher mode misuse ---
	case "modes": // pyca/cryptography: modes.ECB()
		if attr == "ECB" {
			return []Match{ecbMisuse("block cipher", "modes.ECB")}
		}
	case "AES": // pycryptodome: AES.new(key, AES.MODE_ECB)
		if attr == "new" {
			if ecbArg {
				return []Match{ecbMisuse("AES", "AES.MODE_ECB")}
			}
			return []Match{invCipher("AES", "AES.new", "")} // inventory non-ECB AES
		}
	case "ChaCha20", "ChaCha20_Poly1305": // pycryptodome (AEAD) stream ciphers
		if attr == "new" {
			return []Match{invCipher(obj, obj+".new", "")}
		}

	// --- weak symmetric ciphers ---
	case "DES", "DES3", "ARC4", "ARC2", "Blowfish": // pycryptodome ctors
		if attr == "new" {
			alg := pySymAlg(obj)
			out := evalCipher(alg)
			if ecbArg && isBlockCipher(strings.ToUpper(alg)) {
				out = append(out, ecbMisuse(alg, obj+".MODE_ECB"))
			}
			return out
		}
	case "algorithms": // pyca/cryptography algorithm classes
		switch attr {
		case "TripleDES":
			return evalCipher("DESede")
		case "ARC4":
			return evalCipher("RC4")
		case "Blowfish":
			return evalCipher("Blowfish")
		case "AES", "AES128", "AES256", "Camellia", "SM4", "ChaCha20":
			return []Match{invCipher(attr, "algorithms."+attr, "")}
		}

	// --- quantum-vulnerable asymmetric keygen ---
	case "rsa", "ec", "dsa", "dh": // pyca/cryptography
		if attr == "generate_private_key" || attr == "generate_parameters" {
			return evalKeyPairGen(pyAsymAlg(obj))
		}
	case "RSA", "DSA", "ECC": // pycryptodome
		if attr == "generate" {
			return evalKeyPairGen(pyAsymAlg(obj))
		}

	// --- RSA encryption (pycryptodome padding modules) ---
	case "PKCS1_OAEP":
		if attr == "new" {
			return evalCipher("RSA")
		}
	case "PKCS1_v1_5":
		// pycryptodome's Cipher.PKCS1_v1_5 is the v1.5 *encryption* cipher
		// (Bleichenbacher-vulnerable); the signature variant lives in a separate
		// module (Signature.pkcs1_15), so this name is unambiguous.
		if attr == "new" {
			return append(evalCipher("RSA"), rsaPKCS1v15Misuse("PKCS1_v1_5.new"))
		}
	}
	return nil
}

// PyConstructor maps a bare pyca/pycryptodome class or function name — called as a
// constructor (e.g. AESGCM(key), PBKDF2HMAC(...)) rather than obj.method(...) — to an
// inventory match. These are distinctive, crypto-specific identifiers, so matching
// them without import resolution is precise enough for info-severity inventory.
// Returns nil for anything off the curated list, so ordinary bare calls are ignored.
func PyConstructor(name string) []Match {
	switch name {
	// pyca AEAD ciphers (cryptography.hazmat.primitives.ciphers.aead).
	case "AESGCM", "AESCCM", "AESGCMSIV", "AESSIV", "AESOCB3":
		return []Match{aeadCipher("AES", name)}
	case "ChaCha20Poly1305":
		return []Match{aeadCipher("ChaCha20-Poly1305", name)}
	// KDFs — pyca classes and pycryptodome functions.
	case "PBKDF2HMAC", "PBKDF2":
		return []Match{kdfAsset("PBKDF2", name)}
	case "Scrypt", "scrypt":
		return []Match{kdfAsset("scrypt", name)}
	case "HKDF", "HKDFExpand":
		return []Match{kdfAsset("HKDF", name)}
	case "Argon2id":
		return []Match{kdfAsset("Argon2", name)}
	case "X963KDF", "ConcatKDFHash", "ConcatKDFHMAC", "KBKDFHMAC":
		return []Match{kdfAsset(name, name)}
	}
	return nil
}

// pySymAlg maps a Python cipher name to the JCA-style name the shared rules use.
func pySymAlg(obj string) string {
	switch obj {
	case "DES3":
		return "DESede"
	case "ARC4":
		return "RC4"
	case "ARC2":
		return "RC2"
	}
	return obj // DES, Blowfish
}

func pyAsymAlg(obj string) string {
	switch strings.ToUpper(obj) {
	case "RSA":
		return "RSA"
	case "EC", "ECC":
		return "EC"
	case "DSA":
		return "DSA"
	case "DH":
		return "DH"
	}
	return obj
}
