package rules

import (
	"strings"
	"testing"
)

func ruleIDs(ms []Match) string {
	ids := make([]string, len(ms))
	for i, m := range ms {
		ids[i] = m.RuleID
	}
	return strings.Join(ids, ",")
}

func has(ms []Match, ruleID string) bool {
	for _, m := range ms {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestEvaluate(t *testing.T) {
	tests := []struct {
		factory, arg string
		want         []string // rule IDs expected, exact set
	}{
		{"Cipher", "RSA", []string{"CB-ASYM-RSA-CIPHER"}}, // not a block cipher: no default-ECB
		{"Cipher", "AES/ECB/PKCS5Padding", []string{"CB-MISUSE-ECB"}},
		// A bare block-cipher transform makes the JCE default to ECB.
		{"Cipher", "AES", []string{"CB-MISUSE-ECB"}},
		{"Cipher", "DES", []string{"CB-WEAK-DES", "CB-MISUSE-ECB"}},
		// Strong cipher use is inventoried (info), not flagged.
		{"Cipher", "AES/GCM/NoPadding", []string{"CB-INV-CIPHER"}},
		{"Cipher", "AES/CBC/PKCS5Padding", []string{"CB-INV-CIPHER"}},
		{"Cipher", "DES/ECB/PKCS5Padding", []string{"CB-WEAK-DES", "CB-MISUSE-ECB"}},
		{"Cipher", "DESede/CBC/PKCS5Padding", []string{"CB-WEAK-3DES"}},
		{"Cipher", "RC4", []string{"CB-WEAK-RC4"}},
		// RSA's JCE "ECB" pseudo-mode must NOT be flagged as ECB misuse, and OAEP
		// padding is the safe form (no PKCS#1 v1.5 finding).
		{"Cipher", "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", []string{"CB-ASYM-RSA-CIPHER"}},
		// PKCS#1 v1.5 encryption padding is Bleichenbacher-vulnerable.
		{"Cipher", "RSA/ECB/PKCS1Padding", []string{"CB-ASYM-RSA-CIPHER", "CB-MISUSE-RSA-PKCS1V15"}},
		{"MessageDigest", "MD5", []string{"CB-WEAK-MD5"}},
		{"MessageDigest", "SHA-1", []string{"CB-WEAK-SHA1"}},
		{"MessageDigest", "SHA-256", []string{"CB-INV-HASH"}},
		{"KeyPairGenerator", "RSA", []string{"CB-ASYM-RSA-KEYGEN"}},
		{"KeyPairGenerator", "EC", []string{"CB-ASYM-EC-KEYGEN"}},
		{"Signature", "SHA256withRSA", []string{"CB-SIG-RSA"}},
		{"Signature", "SHA1withRSA", []string{"CB-SIG-RSA", "CB-WEAK-SHA1"}},
		{"Signature", "SHA256withECDSA", []string{"CB-SIG-ECDSA"}},
		{"KeyAgreement", "ECDH", []string{"CB-KA-ECDH"}},
		// Weak MAC: HMAC over a broken hash is flagged; strong HMAC is inventoried.
		{"Mac", "HmacMD5", []string{"CB-WEAK-MAC"}},
		{"Mac", "HmacSHA256", []string{"CB-INV-MAC"}},
		{"Mac", "HmacSHA1", []string{"CB-INV-MAC"}},
		// CSPRNG and KDF factories are inventoried.
		{"SecureRandom", "DRBG", []string{"CB-INV-RANDOM"}},
		{"SecureRandom", "SHA1PRNG", []string{"CB-INV-RANDOM"}},
		{"SecretKeyFactory", "PBKDF2WithHmacSHA256", []string{"CB-INV-KDF"}},
		{"SecretKeyFactory", "DES", nil}, // not a KDF -> not inventoried here
		// Strong, modern AEAD is inventoried (info).
		{"Cipher", "ChaCha20-Poly1305", []string{"CB-INV-CIPHER"}},
		{"KeyGenerator", "AES", []string{"CB-INV-SYMKEY"}},
	}

	// .NET HMACMD5 type maps to the same weak-MAC rule.
	if got := CSharpEvaluate("HMACMD5"); !has(got, "CB-WEAK-MAC") {
		t.Errorf("CSharpEvaluate(HMACMD5): missing CB-WEAK-MAC (got [%s])", ruleIDs(got))
	}
	if got := CSharpEvaluate("HMACSHA256"); len(got) != 0 {
		t.Errorf("CSharpEvaluate(HMACSHA256): want none, got [%s]", ruleIDs(got))
	}

	for _, tt := range tests {
		got := Evaluate(tt.factory, tt.arg)
		if len(got) != len(tt.want) {
			t.Errorf("%s(%q): got [%s], want [%s]", tt.factory, tt.arg, ruleIDs(got), strings.Join(tt.want, ","))
			continue
		}
		for _, w := range tt.want {
			if !has(got, w) {
				t.Errorf("%s(%q): missing rule %s (got [%s])", tt.factory, tt.arg, w, ruleIDs(got))
			}
		}
	}
}

func TestCanonHash(t *testing.T) {
	cases := map[string]string{
		"SHA-256":  "SHA-256",
		"SHA256":   "SHA-256",
		"sha512":   "SHA-512",
		"SHA3-256": "SHA3-256",
	}
	for in, want := range cases {
		if got := canonHash(in); got != want {
			t.Errorf("canonHash(%q) = %q, want %q", in, got, want)
		}
	}
}
