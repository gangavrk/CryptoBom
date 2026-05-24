// Sample for cryptobom regression testing. Mixes vulnerable, weak, strong, and
// secure-but-unrelated (crypto/rand) usage. Lives under testdata/ so the Go
// toolchain ignores it; it only needs to parse, not compile.
package samples

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	mrand "math/rand"
)

func vulnerable(msg []byte) {
	// Quantum-vulnerable asymmetric crypto (key sizes / curves captured).
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, _ = rsa.EncryptPKCS1v15(rand.Reader, &rsaKey.PublicKey, msg)
	// Classically weak key size (flagged on top of quantum-vulnerability).
	weakRSA, _ := rsa.GenerateKey(rand.Reader, 1024)
	_, _, _ = ecKey, edPub, weakRSA
}

func weak(key, msg []byte) {
	// Weak / deprecated algorithms.
	_ = md5.Sum(msg)
	_ = sha1.New()
	_, _ = des.NewCipher(key)
	_, _ = des.NewTripleDESCipher(key)
	_, _ = rc4.NewCipher(key)
}

func hardcoded() {
	// Hardcoded key and static IV — literal material in source.
	block, _ := aes.NewCipher([]byte("hardcoded-key-16"))
	_ = cipher.NewCBCEncrypter(block, []byte("0123456789abcdef"))
}

func weakRandomKey() {
	// Key material from math/rand — flagged via sink taint.
	weak := make([]byte, 16)
	mrand.Read(weak)
	_, _ = aes.NewCipher(weak)
	// crypto/rand is correct — must NOT be flagged.
	good := make([]byte, 16)
	rand.Read(good)
	_, _ = aes.NewCipher(good)
}

func strongOrInventory(msg []byte) {
	// Good usage — must NOT be flagged as a problem.
	_ = sha256.Sum256(msg)
	_, _ = rand.Read(make([]byte, 16)) // crypto/rand is the secure RNG, not a finding
}
