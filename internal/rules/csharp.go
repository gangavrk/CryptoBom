package rules

import "strings"

// CSharpEvaluate maps a .NET cryptography type name to matches, reusing the shared
// crypto knowledge. In .NET the algorithm is encoded in the type (MD5, RSA, Aes,
// DESCryptoServiceProvider, …) rather than a string argument, so the analyzer hands
// us the type and we map it. Suffixes like CryptoServiceProvider/Managed/Cng are
// normalized away. Rule identities are shared with the other analyzers.
func CSharpEvaluate(typeName string) []Match {
	switch csNormalizeType(typeName) {
	case "MD5":
		return evalDigest("md5")
	case "SHA1":
		return evalDigest("sha1")
	case "SHA256", "SHA384", "SHA512", "SHA3_256", "SHA3_384", "SHA3_512":
		return evalDigest(typeName)
	case "DES":
		return evalCipher("DES")
	case "TripleDES":
		return evalCipher("DESede")
	case "RC2":
		return evalCipher("RC2")
	case "RSA":
		return evalKeyPairGen("RSA")
	case "DSA":
		return evalKeyPairGen("DSA")
	case "ECDsa":
		return evalKeyPairGen("EC")
	case "ECDiffieHellman":
		return evalKeyAgreement("ECDH")
	case "HMACMD5":
		return evalMac("HmacMD5")
	// .NET 9+ post-quantum types.
	case "MLKem":
		return EvalPQC("ML-KEM")
	case "MLDsa":
		return EvalPQC("ML-DSA")
	case "SlhDsa":
		return EvalPQC("SLH-DSA")
	}
	return nil
}

// CSharpCipherMode flags use of an insecure cipher mode (CipherMode.ECB).
func CSharpCipherMode(mode string) []Match {
	if strings.EqualFold(mode, "ECB") {
		return []Match{ecbMisuse("block cipher", "CipherMode.ECB")}
	}
	return nil
}

// csNormalizeType strips the implementation suffixes .NET appends to algorithm
// types: "DESCryptoServiceProvider" -> "DES", "AesManaged" -> "Aes", "RSACng" -> "RSA".
func csNormalizeType(t string) string {
	for _, suffix := range []string{"CryptoServiceProvider", "Managed", "Cng"} {
		t = strings.TrimSuffix(t, suffix)
	}
	return t
}
