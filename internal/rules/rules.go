// Package rules holds cryptobom's detection rules and the core finding model.
//
// Detection is intentionally precise: callers hand us a recognized JCA factory
// call (e.g. Cipher.getInstance("AES/ECB/PKCS5Padding")) together with the
// string-literal algorithm argument, and we return zero or more matches. We
// favor zero false positives over completeness — when a token is ambiguous
// (e.g. RSA's JCE "ECB" pseudo-mode) we do not flag it.
package rules

import "strings"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type Category string

const (
	CategoryQuantumVulnerable Category = "quantum-vulnerable"
	CategoryWeak              Category = "weak-deprecated"
	CategoryMisuse            Category = "misuse"
	CategoryInventory         Category = "inventory"
	CategoryQuantumSafe       Category = "quantum-safe" // post-quantum algorithm in use (positive)
)

// Match is a rule hit independent of any source location.
type Match struct {
	RuleID      string
	Title       string
	Severity    Severity
	Category    Category
	Algorithm   string   // canonical name, e.g. "RSA", "AES", "SHA-1"
	Detail      string   // spec as written, e.g. "AES/ECB/PKCS5Padding"
	Primitive   string   // CBOM primitive: pke, signature, hash, block-cipher, stream-cipher, key-agree
	Functions   []string // CBOM crypto functions: encrypt, sign, digest, keygen, keyderive...
	Mode        string   // CBOM mode when relevant: ecb, cbc, gcm...
	Remediation string

	// Key parameters, set by AnnotateKey when detected (0 / "" if unknown).
	KeySize       int    // asymmetric key size in bits, e.g. 2048
	Curve         string // normalized elliptic curve, e.g. "P-256"
	ClassicalBits int    // approximate classical security level in bits

	// Non-algorithm CBOM assets.
	AssetKind       string // "" = algorithm (default), "protocol", "certificate", "material"
	ProtocolVersion string // protocol: e.g. "1.1", "3.0"
	MaterialType    string // material: "private-key", "public-key", ...
	CertSubject     string // certificate: subject common name
	CertNotAfter    string // certificate: expiry (RFC3339)
}

// Finding is a Match anchored to a location in a source file.
type Finding struct {
	Match
	File     string
	Line     int // 1-based
	Column   int // 1-based
	Evidence string
	Scope    string // "" for production code, "test" for test code
}

// factories are the JCA entry points we recognize. The analyzer only calls
// Evaluate for calls of the form <Factory>.getInstance("<arg>").
var factories = map[string]bool{
	"Cipher":           true,
	"MessageDigest":    true,
	"KeyPairGenerator": true,
	"KeyGenerator":     true,
	"Signature":        true,
	"KeyAgreement":     true,
	"SSLContext":       true, // SSLContext.getInstance("TLSv1.2") — protocol version
}

// IsFactory reports whether className is a recognized JCA crypto factory.
func IsFactory(className string) bool { return factories[className] }

// Evaluate inspects a JCA factory call and returns any matches.
func Evaluate(factory, arg string) []Match {
	arg = strings.TrimSpace(arg)
	// A post-quantum algorithm name short-circuits any factory (e.g. BouncyCastle
	// KeyPairGenerator.getInstance("ML-KEM")).
	if m := EvalPQC(arg); len(m) > 0 {
		return m
	}
	switch factory {
	case "Cipher":
		return evalCipher(arg)
	case "MessageDigest":
		return evalDigest(arg)
	case "KeyPairGenerator":
		return evalKeyPairGen(arg)
	case "KeyGenerator":
		return evalKeyGen(arg)
	case "Signature":
		return evalSignature(arg)
	case "KeyAgreement":
		return evalKeyAgreement(arg)
	case "SSLContext":
		return EvalProtocol(arg)
	}
	return nil
}

func evalCipher(transform string) []Match {
	parts := strings.Split(transform, "/")
	alg := strings.TrimSpace(parts[0])
	mode := ""
	if len(parts) >= 2 {
		mode = strings.TrimSpace(parts[1])
	}
	up := strings.ToUpper(alg)

	var out []Match
	switch up {
	case "RSA":
		out = append(out, Match{
			RuleID: "CB-ASYM-RSA-CIPHER", Title: "RSA encryption is quantum-vulnerable",
			Severity: SeverityHigh, Category: CategoryQuantumVulnerable,
			Algorithm: "RSA", Detail: transform, Primitive: "pke",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Plan migration to a NIST PQC KEM (ML-KEM / FIPS 203), or a hybrid scheme during transition.",
		})
	case "DES":
		out = append(out, Match{
			RuleID: "CB-WEAK-DES", Title: "DES is a broken 56-bit cipher",
			Severity: SeverityHigh, Category: CategoryWeak,
			Algorithm: "DES", Detail: transform, Primitive: "block-cipher",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Replace with AES-256 in an authenticated mode (GCM).",
		})
	case "DESEDE", "TRIPLEDES", "3DES":
		out = append(out, Match{
			RuleID: "CB-WEAK-3DES", Title: "3DES (DESede) is deprecated",
			Severity: SeverityMedium, Category: CategoryWeak,
			Algorithm: "3DES", Detail: transform, Primitive: "block-cipher",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Replace with AES-256 (GCM); NIST disallows 3DES after 2023.",
		})
	case "RC4", "ARCFOUR":
		out = append(out, Match{
			RuleID: "CB-WEAK-RC4", Title: "RC4 is a broken stream cipher",
			Severity: SeverityHigh, Category: CategoryWeak,
			Algorithm: "RC4", Detail: transform, Primitive: "stream-cipher",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Replace with AES-GCM or ChaCha20-Poly1305.",
		})
	case "BLOWFISH":
		out = append(out, Match{
			RuleID: "CB-WEAK-BLOWFISH", Title: "Blowfish has a 64-bit block (birthday-bound risk)",
			Severity: SeverityMedium, Category: CategoryWeak,
			Algorithm: "Blowfish", Detail: transform, Primitive: "block-cipher",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Replace with AES-256 (GCM).",
		})
	case "RC2":
		out = append(out, Match{
			RuleID: "CB-WEAK-RC2", Title: "RC2 is a weak 64-bit block cipher",
			Severity: SeverityMedium, Category: CategoryWeak,
			Algorithm: "RC2", Detail: transform, Primitive: "block-cipher",
			Functions:   []string{"encrypt", "decrypt"},
			Remediation: "Replace with AES-256 (GCM).",
		})
	}

	// ECB is only a misuse for symmetric block ciphers. RSA's "ECB" token in
	// the JCE is a historical quirk, not real ECB — flagging it is a false positive.
	if strings.EqualFold(mode, "ECB") && isBlockCipher(up) {
		out = append(out, ecbMisuse(alg, transform))
	}
	return out
}

// ecbMisuse builds the shared ECB-mode misuse match. alg is the cipher (used as
// the asset name) and detail is the spec as written (transform or call form).
func ecbMisuse(alg, detail string) Match {
	return Match{
		RuleID: "CB-MISUSE-ECB", Title: "ECB mode leaks plaintext structure",
		Severity: SeverityHigh, Category: CategoryMisuse,
		Algorithm: alg, Detail: detail, Primitive: "block-cipher", Mode: "ecb",
		Functions:   []string{"encrypt", "decrypt"},
		Remediation: "Use an authenticated mode such as GCM; never ECB.",
	}
}

func evalDigest(alg string) []Match {
	switch normHash(alg) {
	case "MD5", "MD2", "MD4":
		return []Match{{
			RuleID: "CB-WEAK-" + normHash(alg), Title: strings.ToUpper(alg) + " is a broken hash (practical collisions)",
			Severity: SeverityHigh, Category: CategoryWeak,
			Algorithm: strings.ToUpper(alg), Detail: alg, Primitive: "hash",
			Functions:   []string{"digest"},
			Remediation: "Replace with SHA-256 or SHA-3.",
		}}
	case "SHA1":
		return []Match{{
			RuleID: "CB-WEAK-SHA1", Title: "SHA-1 is deprecated (collision attacks)",
			Severity: SeverityMedium, Category: CategoryWeak,
			Algorithm: "SHA-1", Detail: alg, Primitive: "hash",
			Functions:   []string{"digest"},
			Remediation: "Replace with SHA-256 or SHA-3.",
		}}
	}
	if strings.HasPrefix(normHash(alg), "SHA") {
		return []Match{{
			RuleID: "CB-INV-HASH", Title: "Hash function in use",
			Severity: SeverityInfo, Category: CategoryInventory,
			Algorithm: canonHash(alg), Detail: alg, Primitive: "hash",
			Functions: []string{"digest"},
		}}
	}
	return nil
}

func evalKeyPairGen(alg string) []Match {
	switch strings.ToUpper(alg) {
	case "RSA":
		return []Match{qv("CB-ASYM-RSA-KEYGEN", "RSA", "RSA key generation is quantum-vulnerable",
			"pke", []string{"keygen"}, alg,
			"Migrate to ML-KEM (FIPS 203) for key establishment or ML-DSA (FIPS 204) for signatures.")}
	case "EC", "ECDSA":
		return []Match{qv("CB-ASYM-EC-KEYGEN", "ECDSA", "Elliptic-curve key generation is quantum-vulnerable",
			"signature", []string{"keygen"}, alg,
			"Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).")}
	case "DSA":
		return []Match{qv("CB-ASYM-DSA-KEYGEN", "DSA", "DSA key generation is quantum-vulnerable and legacy",
			"signature", []string{"keygen"}, alg, "Migrate to ML-DSA (FIPS 204).")}
	case "DH", "DIFFIEHELLMAN":
		return []Match{qv("CB-ASYM-DH-KEYGEN", "DH", "Diffie-Hellman key generation is quantum-vulnerable",
			"key-agree", []string{"keygen"}, alg, "Migrate to ML-KEM (FIPS 203).")}
	case "ED25519", "ED448", "EDDSA":
		return []Match{qv("CB-ASYM-EDDSA-KEYGEN", "EdDSA", "EdDSA key generation is quantum-vulnerable",
			"signature", []string{"keygen"}, alg, "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205).")}
	case "X25519", "X448", "XDH":
		return []Match{qv("CB-ASYM-XDH-KEYGEN", "XDH", "X25519/X448 key agreement is quantum-vulnerable",
			"key-agree", []string{"keygen"}, alg, "Migrate to ML-KEM (FIPS 203).")}
	}
	return nil
}

func evalKeyGen(alg string) []Match {
	switch strings.ToUpper(alg) {
	case "DES":
		return []Match{{RuleID: "CB-WEAK-DES", Title: "DES key generation (broken 56-bit cipher)",
			Severity: SeverityHigh, Category: CategoryWeak, Algorithm: "DES", Detail: alg,
			Primitive: "block-cipher", Functions: []string{"keygen"}, Remediation: "Replace with AES-256."}}
	case "DESEDE", "TRIPLEDES", "3DES":
		return []Match{{RuleID: "CB-WEAK-3DES", Title: "3DES key generation (deprecated)",
			Severity: SeverityMedium, Category: CategoryWeak, Algorithm: "3DES", Detail: alg,
			Primitive: "block-cipher", Functions: []string{"keygen"}, Remediation: "Replace with AES-256."}}
	case "RC4", "ARCFOUR":
		return []Match{{RuleID: "CB-WEAK-RC4", Title: "RC4 key generation (broken stream cipher)",
			Severity: SeverityHigh, Category: CategoryWeak, Algorithm: "RC4", Detail: alg,
			Primitive: "stream-cipher", Functions: []string{"keygen"}, Remediation: "Replace with AES-GCM or ChaCha20-Poly1305."}}
	case "AES":
		return []Match{{RuleID: "CB-INV-SYMKEY", Title: "Symmetric key generation in use",
			Severity: SeverityInfo, Category: CategoryInventory, Algorithm: "AES", Detail: alg,
			Primitive: "block-cipher", Functions: []string{"keygen"}}}
	}
	return nil
}

func evalSignature(alg string) []Match {
	up := strings.ToUpper(alg)
	var out []Match
	switch {
	case strings.Contains(up, "ECDSA"):
		out = append(out, qv("CB-SIG-ECDSA", "ECDSA", "ECDSA signatures are quantum-vulnerable",
			"signature", []string{"sign", "verify"}, alg, "Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."))
	case strings.Contains(up, "RSA"):
		out = append(out, qv("CB-SIG-RSA", "RSA", "RSA signatures are quantum-vulnerable",
			"signature", []string{"sign", "verify"}, alg, "Migrate to ML-DSA (FIPS 204)."))
	case strings.Contains(up, "DSA"):
		out = append(out, qv("CB-SIG-DSA", "DSA", "DSA signatures are quantum-vulnerable and legacy",
			"signature", []string{"sign", "verify"}, alg, "Migrate to ML-DSA (FIPS 204)."))
	}
	// The digest half of the signature algorithm may itself be weak.
	if strings.HasPrefix(up, "MD5") {
		out = append(out, Match{RuleID: "CB-WEAK-MD5", Title: "MD5 used as a signature digest (broken)",
			Severity: SeverityHigh, Category: CategoryWeak, Algorithm: "MD5", Detail: alg,
			Primitive: "hash", Functions: []string{"digest"}, Remediation: "Use at least SHA-256 in signatures."})
	} else if strings.HasPrefix(up, "SHA1") {
		out = append(out, Match{RuleID: "CB-WEAK-SHA1", Title: "SHA-1 used as a signature digest (deprecated)",
			Severity: SeverityMedium, Category: CategoryWeak, Algorithm: "SHA-1", Detail: alg,
			Primitive: "hash", Functions: []string{"digest"}, Remediation: "Use at least SHA-256 in signatures."})
	}
	return out
}

func evalKeyAgreement(alg string) []Match {
	switch strings.ToUpper(strings.TrimSpace(alg)) {
	case "ECDH":
		return []Match{qv("CB-KA-ECDH", "ECDH", "ECDH key agreement is quantum-vulnerable",
			"key-agree", []string{"keyderive"}, alg, "Migrate to ML-KEM (FIPS 203).")}
	case "DH", "DIFFIEHELLMAN":
		return []Match{qv("CB-KA-DH", "DH", "Diffie-Hellman key agreement is quantum-vulnerable",
			"key-agree", []string{"keyderive"}, alg, "Migrate to ML-KEM (FIPS 203).")}
	}
	return nil
}

// qv builds a quantum-vulnerable (high-severity) match.
func qv(ruleID, algo, title, primitive string, fns []string, detail, remediation string) Match {
	return Match{
		RuleID: ruleID, Title: title, Severity: SeverityHigh,
		Category: CategoryQuantumVulnerable, Algorithm: algo, Detail: detail,
		Primitive: primitive, Functions: fns, Remediation: remediation,
	}
}

func isBlockCipher(up string) bool {
	switch up {
	case "AES", "DES", "DESEDE", "TRIPLEDES", "3DES", "BLOWFISH", "RC2",
		"CAMELLIA", "ARIA", "SEED", "IDEA", "CAST5", "CAST6", "TWOFISH":
		return true
	}
	return false
}

// normHash uppercases and strips separators: "SHA-1" -> "SHA1", "sha_256" -> "SHA256".
func normHash(alg string) string {
	r := strings.NewReplacer("-", "", "_", "", " ", "")
	return strings.ToUpper(r.Replace(alg))
}

// canonHash renders a display name with the conventional dash: "SHA256" -> "SHA-256".
func canonHash(alg string) string {
	n := normHash(alg)
	if rest, ok := strings.CutPrefix(n, "SHA3"); ok {
		if rest == "" {
			return "SHA3"
		}
		return "SHA3-" + rest
	}
	if rest, ok := strings.CutPrefix(n, "SHA"); ok && rest != "" {
		return "SHA-" + rest
	}
	return n
}
