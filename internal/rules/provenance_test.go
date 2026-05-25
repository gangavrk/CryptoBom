package rules

import (
	"strings"
	"testing"
)

// emittedRuleIDs is every rule ID the analyzers can produce. The completeness test
// fails if any of these lacks provenance — so a new rule can't ship untraceable.
var emittedRuleIDs = []string{
	"CB-ASYM-RSA-CIPHER", "CB-ASYM-RSA-KEYGEN", "CB-ASYM-EC-KEYGEN", "CB-ASYM-DSA-KEYGEN",
	"CB-ASYM-DH-KEYGEN", "CB-ASYM-EDDSA-KEYGEN", "CB-ASYM-XDH-KEYGEN", "CB-ASYM-ED25519",
	"CB-SIG-RSA", "CB-SIG-ECDSA", "CB-SIG-DSA", "CB-KA-ECDH", "CB-KA-DH",
	"CB-CERT-KEY-RSA", "CB-CERT-KEY-EC", "CB-CERT-KEY-ED25519", "CB-CERT-KEY-DSA",
	"CB-WEAK-MD5", "CB-WEAK-MD4", "CB-WEAK-MD2", "CB-WEAK-SHA1",
	"CB-WEAK-DES", "CB-WEAK-3DES", "CB-WEAK-RC4", "CB-WEAK-RC2", "CB-WEAK-BLOWFISH",
	"CB-WEAK-KEYSIZE", "CB-WEAK-CURVE", "CB-WEAK-CERT-SIG", "CB-CERT-EXPIRED",
	"CB-MISUSE-ECB", "CB-MISUSE-STATIC-IV", "CB-MISUSE-HARDCODED-KEY",
	"CB-MISUSE-WEAK-PRNG", "CB-MISUSE-TIMING-COMPARE",
	"CB-WEAK-PROTOCOL", "CB-WEAK-CIPHERSUITE",
	"CB-MATERIAL-PRIVATE-KEY", "CB-MATERIAL-KEYSTORE", "CB-PQC",
	"CB-INV-HASH", "CB-INV-PROTOCOL", "CB-INV-SYMKEY", "CB-INV-PUBLIC-KEY", "CB-INV-CERTIFICATE",
}

func TestEveryRuleHasProvenance(t *testing.T) {
	for _, id := range emittedRuleIDs {
		if _, ok := ProvenanceFor(id); !ok {
			t.Errorf("rule %s has no provenance entry", id)
		}
	}
}

func TestProvenanceWellFormed(t *testing.T) {
	for id, p := range catalog {
		switch p.Status {
		case StatusFinalized, StatusDraft, StatusGuidance:
		default:
			t.Errorf("%s: invalid status %q", id, p.Status)
		}
		if len(p.References) == 0 {
			t.Errorf("%s: no references", id)
		}
		for _, r := range p.References {
			if r.Authority == "" || r.ID == "" || !strings.HasPrefix(r.URL, "https://") {
				t.Errorf("%s: malformed reference %+v", id, r)
			}
		}
	}
}
