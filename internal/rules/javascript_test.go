package rules

import (
	"strings"
	"testing"
)

func TestJSEvaluate(t *testing.T) {
	tests := []struct {
		obj, method, arg string
		want             []string // exact set of rule IDs
	}{
		// Node.js crypto
		{"crypto", "createHash", "md5", []string{"CB-WEAK-MD5"}},
		{"crypto", "createHash", "sha256", []string{"CB-INV-HASH"}},
		{"crypto", "createHmac", "md5", []string{"CB-WEAK-MAC"}},   // HMAC-MD5 is weak
		{"crypto", "createHmac", "sha256", []string{"CB-INV-MAC"}}, // HMAC-SHA-256 inventoried
		{"crypto", "createHmac", "sha1", []string{"CB-INV-MAC"}},   // HMAC-SHA1 is not broken
		{"crypto", "createCipheriv", "aes-128-ecb", []string{"CB-MISUSE-ECB"}},
		{"crypto", "createCipheriv", "aes-256-gcm", []string{"CB-INV-CIPHER"}},
		{"crypto", "createCipheriv", "des-ede3-cbc", []string{"CB-WEAK-3DES"}},
		{"crypto", "generateKeyPair", "rsa", []string{"CB-ASYM-RSA-KEYGEN"}},
		{"crypto", "randomBytes", "", []string{"CB-INV-RANDOM"}},
		{"crypto", "getRandomValues", "", []string{"CB-INV-RANDOM"}},
		{"crypto", "pbkdf2", "", []string{"CB-INV-KDF"}},
		{"crypto", "scryptSync", "", []string{"CB-INV-KDF"}},
		// crypto-js
		{"CryptoJS", "MD5", "", []string{"CB-WEAK-MD5"}},
		{"CryptoJS", "DES", "", []string{"CB-WEAK-DES"}},
		{"mode", "ECB", "", []string{"CB-MISUSE-ECB"}},
		// unrelated
		{"crypto", "randomFoo", "", nil},
		{"express", "listen", "", nil},
	}
	for _, tt := range tests {
		got := JSEvaluate(tt.obj, tt.method, tt.arg)
		if len(got) != len(tt.want) {
			t.Errorf("JSEvaluate(%q,%q,%q): got [%s], want [%s]",
				tt.obj, tt.method, tt.arg, ruleIDs(got), strings.Join(tt.want, ","))
			continue
		}
		for _, w := range tt.want {
			if !has(got, w) {
				t.Errorf("JSEvaluate(%q,%q,%q): missing %s (got [%s])",
					tt.obj, tt.method, tt.arg, w, ruleIDs(got))
			}
		}
	}
}
