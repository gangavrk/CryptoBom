package rules

import (
	"strings"
	"testing"
)

func TestGoEvaluate(t *testing.T) {
	tests := []struct {
		path, fn string
		want     []string // exact set of rule IDs
	}{
		{"crypto/md5", "Sum", []string{"CB-WEAK-MD5"}},
		{"crypto/md5", "New", []string{"CB-WEAK-MD5"}},
		{"crypto/sha1", "New", []string{"CB-WEAK-SHA1"}},
		{"crypto/sha256", "Sum256", []string{"CB-INV-HASH"}},
		{"crypto/sha512", "New384", []string{"CB-INV-HASH"}},
		{"crypto/des", "NewCipher", []string{"CB-WEAK-DES"}},
		{"crypto/des", "NewTripleDESCipher", []string{"CB-WEAK-3DES"}},
		{"crypto/rc4", "NewCipher", []string{"CB-WEAK-RC4"}},
		{"crypto/rsa", "GenerateKey", []string{"CB-ASYM-RSA-KEYGEN"}},
		{"crypto/rsa", "EncryptOAEP", []string{"CB-ASYM-RSA-CIPHER"}},
		// PKCS#1 v1.5 *encryption* is Bleichenbacher-vulnerable; *signing* is not.
		{"crypto/rsa", "EncryptPKCS1v15", []string{"CB-ASYM-RSA-CIPHER", "CB-MISUSE-RSA-PKCS1V15"}},
		{"crypto/rsa", "SignPKCS1v15", []string{"CB-SIG-RSA"}},
		{"crypto/rsa", "SignPSS", []string{"CB-SIG-RSA"}},
		{"crypto/ecdsa", "GenerateKey", []string{"CB-ASYM-EC-KEYGEN"}},
		{"crypto/ecdsa", "SignASN1", []string{"CB-SIG-ECDSA"}},
		{"crypto/ed25519", "GenerateKey", []string{"CB-ASYM-ED25519"}},
		{"crypto/dsa", "GenerateKey", []string{"CB-ASYM-DSA-KEYGEN"}},
		{"crypto/ecdh", "X25519", []string{"CB-KA-ECDH"}},
		// Inventory: strong/neutral assets (info-severity).
		{"crypto/rand", "Read", []string{"CB-INV-RANDOM"}},
		{"crypto/aes", "NewCipher", []string{"CB-INV-CIPHER"}},
		{"crypto/hmac", "New", []string{"CB-INV-MAC"}},
		{"golang.org/x/crypto/pbkdf2", "Key", []string{"CB-INV-KDF"}},
		{"golang.org/x/crypto/argon2", "IDKey", []string{"CB-INV-KDF"}},
		{"golang.org/x/crypto/chacha20poly1305", "New", []string{"CB-INV-CIPHER"}},
		// Unrelated usage must produce nothing.
		{"crypto/sha256", "Size", nil}, // constant access, not a hashing call
		{"crypto/rsa", "PublicKey", nil},
		{"fmt", "Println", nil},
	}

	for _, tt := range tests {
		got := GoEvaluate(tt.path, tt.fn)
		if len(got) != len(tt.want) {
			t.Errorf("GoEvaluate(%q,%q): got [%s], want [%s]",
				tt.path, tt.fn, ruleIDs(got), strings.Join(tt.want, ","))
			continue
		}
		for _, w := range tt.want {
			if !has(got, w) {
				t.Errorf("GoEvaluate(%q,%q): missing %s (got [%s])", tt.path, tt.fn, w, ruleIDs(got))
			}
		}
	}
}
