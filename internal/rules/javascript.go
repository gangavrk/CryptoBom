package rules

import "strings"

var jsCryptoHashes = map[string]bool{
	"MD5": true, "SHA1": true, "SHA224": true, "SHA256": true,
	"SHA384": true, "SHA512": true, "SHA3": true,
}

// JSEvaluate maps a recognized JS/TS crypto call/member to matches. The analyzer
// supplies the receiver (obj), the method/property, and the first string argument:
//
//	crypto.createHash("md5") / createCipheriv("aes-128-ecb", …) / generateKeyPair("rsa", …)
//	CryptoJS.MD5(…) / CryptoJS.DES.encrypt(…)
//	*.mode.ECB  (obj == "mode")
func JSEvaluate(obj, method, arg string) []Match {
	switch obj {
	case "crypto": // Node.js crypto module
		switch method {
		case "createHash", "createHmac":
			if m := EvalPQC(arg); len(m) > 0 {
				return m
			}
			return evalDigest(arg)
		case "createCipheriv", "createCipher":
			return evalCipher(opensslCipherToTransform(arg))
		case "generateKeyPair", "generateKeyPairSync":
			if m := EvalPQC(arg); len(m) > 0 {
				return m
			}
			return evalKeyPairGen(strings.ToUpper(arg))
		}
	case "CryptoJS": // crypto-js library
		if jsCryptoHashes[method] {
			return evalDigest(method)
		}
		switch method {
		case "DES":
			return evalCipher("DES")
		case "TripleDES":
			return evalCipher("DESede")
		case "RC4", "RC4Drop":
			return evalCipher("RC4")
		}
	case "mode": // CryptoJS.mode.ECB
		if method == "ECB" {
			return []Match{ecbMisuse("block cipher", "CryptoJS.mode.ECB")}
		}
	}
	return nil
}

// opensslCipherToTransform converts an OpenSSL cipher name ("aes-128-ecb",
// "des-ede3-cbc", "rc4") to a JCA-style "ALG/MODE" the shared evalCipher understands.
func opensslCipherToTransform(s string) string {
	l := strings.ToLower(s)
	var algo string
	switch {
	case strings.Contains(l, "des-ede3"), strings.Contains(l, "des3"), strings.HasPrefix(l, "3des"):
		algo = "DESede"
	case strings.Contains(l, "des"):
		algo = "DES"
	case strings.Contains(l, "rc4"):
		algo = "RC4"
	case strings.Contains(l, "rc2"):
		algo = "RC2"
	case strings.HasPrefix(l, "bf"), strings.Contains(l, "blowfish"):
		algo = "Blowfish"
	case strings.Contains(l, "aes"):
		algo = "AES"
	default:
		algo = s
	}
	for _, m := range []string{"ecb", "gcm", "cbc", "ctr", "cfb", "ofb"} {
		if strings.Contains(l, m) {
			return algo + "/" + strings.ToUpper(m)
		}
	}
	return algo
}
