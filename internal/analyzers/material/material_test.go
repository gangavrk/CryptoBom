package material

import (
	"encoding/pem"
	"testing"
)

func TestIsMaterialFile(t *testing.T) {
	yes := []string{"server.pem", "tls.crt", "ca.cer", "cert.der", "private.key",
		"key.p12", "store.pfx", "keystore.jks", "id_rsa", "id_ed25519", "authorized_keys", "deploy.pub"}
	for _, n := range yes {
		if !IsMaterialFile(n) {
			t.Errorf("IsMaterialFile(%q) = false, want true", n)
		}
	}
	no := []string{"main.go", "README.md", "config.json", "app.py", "keyboard.ts"}
	for _, n := range no {
		if IsMaterialFile(n) {
			t.Errorf("IsMaterialFile(%q) = true, want false", n)
		}
	}
}

func TestClassifyPEMPrivateKey(t *testing.T) {
	got := classifyPEM(&pem.Block{Type: "RSA PRIVATE KEY"})
	if len(got) != 1 || got[0].RuleID != "CB-MATERIAL-PRIVATE-KEY" {
		t.Fatalf("RSA PRIVATE KEY: got %+v, want CB-MATERIAL-PRIVATE-KEY", got)
	}
	if got[0].Algorithm != "RSA private key" {
		t.Errorf("algorithm = %q, want %q", got[0].Algorithm, "RSA private key")
	}
}

func TestLabelAlgo(t *testing.T) {
	cases := map[string]string{
		"RSA PRIVATE KEY": "RSA", "EC PRIVATE KEY": "EC",
		"OPENSSH PRIVATE KEY": "SSH", "PRIVATE KEY": "", "PUBLIC KEY": "",
	}
	for in, want := range cases {
		if got := labelAlgo(in); got != want {
			t.Errorf("labelAlgo(%q) = %q, want %q", in, got, want)
		}
	}
}
