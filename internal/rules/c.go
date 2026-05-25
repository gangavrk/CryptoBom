package rules

import "strings"

var cDigestNames = map[string]bool{
	"MD5": true, "MD4": true, "MD2": true, "SHA1": true,
	"SHA224": true, "SHA256": true, "SHA384": true, "SHA512": true,
}

var cVersionConst = map[string]string{
	"SSL2_VERSION": "SSLv2", "SSL3_VERSION": "SSLv3",
	"TLS1_VERSION": "TLSv1.0", "TLS1_1_VERSION": "TLSv1.1",
	"TLS1_2_VERSION": "TLSv1.2", "TLS1_3_VERSION": "TLSv1.3",
}

func cipherToken(s string) bool {
	for _, t := range []string{"aes", "des", "rc4", "rc2", "bf", "blowfish",
		"cast", "camellia", "chacha", "seed", "idea", "aria", "sm4"} {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}

// CEvaluate maps an OpenSSL function name (and any string argument) to matches.
// Covers the function-name-encoded API (EVP_des_ede3_cbc, MD5, RSA_generate_key_ex),
// the 3.0 fetch API (EVP_MD_fetch("MD5"), EVP_CIPHER_fetch("AES-128-ECB")), and TLS
// protocol method constructors (SSLv3_method, TLSv1_1_method).
func CEvaluate(funcName, strArg string) []Match {
	switch funcName {
	case "EVP_MD_fetch":
		return evalDigest(strArg)
	case "EVP_CIPHER_fetch":
		return evalCipher(opensslCipherToTransform(strArg))
	}

	// TLS protocol method: <proto>_method / _client_method / _server_method
	if strings.HasSuffix(funcName, "_method") {
		p := strings.TrimSuffix(funcName, "_method")
		p = strings.TrimSuffix(strings.TrimSuffix(p, "_client"), "_server")
		if m := EvalProtocol(p); len(m) > 0 {
			return m
		}
	}

	// EVP_* digest / cipher constructors.
	if rest, ok := strings.CutPrefix(funcName, "EVP_"); ok {
		l := strings.ToLower(rest)
		switch {
		case l == "md5" || l == "md4" || l == "md2" || strings.HasPrefix(l, "sha"):
			return evalDigest(l)
		case cipherToken(l):
			return evalCipher(opensslCipherToTransform(strings.ReplaceAll(l, "_", "-")))
		}
		return nil
	}

	// Direct hash functions: MD5, MD5_Init, SHA1, SHA256_Init (not Update/Final).
	base, suffix, _ := strings.Cut(funcName, "_")
	if cDigestNames[base] && (suffix == "" || suffix == "Init") {
		return evalDigest(base)
	}

	// Asymmetric key generation.
	switch {
	case strings.HasPrefix(funcName, "RSA_generate_key"):
		return evalKeyPairGen("RSA")
	case strings.HasPrefix(funcName, "DSA_generate"):
		return evalKeyPairGen("DSA")
	case strings.HasPrefix(funcName, "DH_generate"):
		return evalKeyPairGen("DH")
	case funcName == "EC_KEY_generate_key" || funcName == "EC_KEY_new_by_curve_name":
		return evalKeyPairGen("EC")
	}
	return nil
}

// CVersionConst maps an OpenSSL version constant (TLS1_1_VERSION, …) to matches.
func CVersionConst(name string) []Match {
	if tok, ok := cVersionConst[name]; ok {
		return EvalProtocol(tok)
	}
	return nil
}
