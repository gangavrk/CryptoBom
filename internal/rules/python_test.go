package rules

import (
	"strings"
	"testing"
)

func TestPyEvaluate(t *testing.T) {
	tests := []struct {
		obj, attr, strArg string
		ecb               bool
		want              []string // exact set of rule IDs
	}{
		{"hashlib", "md5", "", false, []string{"CB-WEAK-MD5"}},
		{"hashlib", "sha1", "", false, []string{"CB-WEAK-SHA1"}},
		{"hashlib", "new", "sha1", false, []string{"CB-WEAK-SHA1"}},
		{"hashlib", "sha256", "", false, []string{"CB-INV-HASH"}},
		{"hashlib", "new", "", false, nil}, // non-literal arg -> ignored
		{"hashes", "SHA1", "", false, []string{"CB-WEAK-SHA1"}},
		{"hashes", "SHA256", "", false, []string{"CB-INV-HASH"}},
		{"MD5", "new", "", false, []string{"CB-WEAK-MD5"}}, // pycryptodome Crypto.Hash.MD5
		{"modes", "ECB", "", false, []string{"CB-MISUSE-ECB"}},
		{"modes", "GCM", "", false, nil},
		{"AES", "new", "", true, []string{"CB-MISUSE-ECB"}},
		{"AES", "new", "", false, nil}, // AES without ECB is fine
		{"DES", "new", "", true, []string{"CB-WEAK-DES", "CB-MISUSE-ECB"}},
		{"DES3", "new", "", false, []string{"CB-WEAK-3DES"}},
		{"algorithms", "TripleDES", "", false, []string{"CB-WEAK-3DES"}},
		{"algorithms", "AES", "", false, nil},
		{"rsa", "generate_private_key", "", false, []string{"CB-ASYM-RSA-KEYGEN"}},
		{"ec", "generate_private_key", "", false, []string{"CB-ASYM-EC-KEYGEN"}},
		{"RSA", "generate", "", false, []string{"CB-ASYM-RSA-KEYGEN"}},
		{"ECC", "generate", "", false, []string{"CB-ASYM-EC-KEYGEN"}},
		{"PKCS1_OAEP", "new", "", false, []string{"CB-ASYM-RSA-CIPHER"}},
		{"PKCS1_v1_5", "new", "", false, []string{"CB-ASYM-RSA-CIPHER", "CB-MISUSE-RSA-PKCS1V15"}},
		{"json", "loads", "", false, nil}, // unrelated call -> nothing
	}

	for _, tt := range tests {
		got := PyEvaluate(tt.obj, tt.attr, tt.strArg, tt.ecb)
		if len(got) != len(tt.want) {
			t.Errorf("PyEvaluate(%q,%q,%q,%v): got [%s], want [%s]",
				tt.obj, tt.attr, tt.strArg, tt.ecb, ruleIDs(got), strings.Join(tt.want, ","))
			continue
		}
		for _, w := range tt.want {
			if !has(got, w) {
				t.Errorf("PyEvaluate(%q,%q,%q,%v): missing %s (got [%s])",
					tt.obj, tt.attr, tt.strArg, tt.ecb, w, ruleIDs(got))
			}
		}
	}
}
