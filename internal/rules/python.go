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

	// --- hashes ---
	case "hashlib":
		if attr == "new" {
			return evalDigest(strArg)
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
		if attr == "new" && ecbArg {
			return []Match{ecbMisuse("AES", "AES.MODE_ECB")}
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
	case "PKCS1_OAEP", "PKCS1_v1_5":
		if attr == "new" {
			return evalCipher("RSA")
		}
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
