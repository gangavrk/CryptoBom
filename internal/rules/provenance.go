package rules

// RulePackVersion identifies the version of the detection-rule catalog. It is
// stamped into every report so a finding can be traced to the exact ruleset that
// produced it.
const RulePackVersion = "2026.05.1"

// StandardStatus records whether a rule's basis is a finalized standard, a draft,
// or industry guidance — so a reader knows how settled the underlying authority is.
type StandardStatus string

const (
	StatusFinalized StandardStatus = "finalized"
	StatusDraft     StandardStatus = "draft"
	StatusGuidance  StandardStatus = "guidance"
)

// Reference is a citation to the authority a rule is based on.
type Reference struct {
	Authority string // NIST, NSA, IETF, OWASP, MITRE
	ID        string // FIPS 203, SP 800-131A Rev.2, RFC 8996, …
	URL       string
}

func (r Reference) String() string { return r.Authority + " " + r.ID }

// Provenance is the verifiable basis of a rule: the weakness class (CWE), the
// status of the underlying standard, and the citations that justify the rule.
type Provenance struct {
	CWE        []string
	Status     StandardStatus
	References []Reference
}

// ProvenanceFor returns the provenance recorded for a rule ID.
func ProvenanceFor(ruleID string) (Provenance, bool) {
	p, ok := catalog[ruleID]
	return p, ok
}

// --- authoritative sources ---
var (
	refCNSA2     = Reference{"NSA", "CNSA 2.0", "https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF"}
	refIR8547    = Reference{"NIST", "IR 8547 (PQC transition)", "https://csrc.nist.gov/pubs/ir/8547/ipd"}
	refFIPS203   = Reference{"NIST", "FIPS 203 (ML-KEM)", "https://csrc.nist.gov/pubs/fips/203/final"}
	refFIPS204   = Reference{"NIST", "FIPS 204 (ML-DSA)", "https://csrc.nist.gov/pubs/fips/204/final"}
	refFIPS205   = Reference{"NIST", "FIPS 205 (SLH-DSA)", "https://csrc.nist.gov/pubs/fips/205/final"}
	refSP800131A = Reference{"NIST", "SP 800-131A Rev.2", "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"}
	refSP80057   = Reference{"NIST", "SP 800-57 Part 1 Rev.5", "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final"}
	refSP80052   = Reference{"NIST", "SP 800-52 Rev.2 (TLS)", "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}
	refSP80038A  = Reference{"NIST", "SP 800-38A (modes of operation)", "https://csrc.nist.gov/pubs/sp/800/38/a/final"}
	refSP80090A  = Reference{"NIST", "SP 800-90A Rev.1 (DRBG)", "https://csrc.nist.gov/pubs/sp/800/90/a/r1/final"}
	refRFC8996   = Reference{"IETF", "RFC 8996 (deprecate TLS 1.0/1.1)", "https://www.rfc-editor.org/rfc/rfc8996"}
	refRFC7568   = Reference{"IETF", "RFC 7568 (deprecate SSLv3)", "https://www.rfc-editor.org/rfc/rfc7568"}
	refRFC6151   = Reference{"IETF", "RFC 6151 (MD5)", "https://www.rfc-editor.org/rfc/rfc6151"}
	refRFC5280   = Reference{"IETF", "RFC 5280 (X.509)", "https://www.rfc-editor.org/rfc/rfc5280"}
	refOWASPCS   = Reference{"OWASP", "Cryptographic Storage Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"}
	refOWASPSec  = Reference{"OWASP", "Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}
)

// --- reusable provenance profiles ---
var (
	pvQuantum    = Provenance{[]string{"CWE-327"}, StatusFinalized, []Reference{refCNSA2, refIR8547, refFIPS203, refFIPS204}}
	pvWeakHash   = Provenance{[]string{"CWE-328"}, StatusFinalized, []Reference{refSP800131A}}
	pvMD5        = Provenance{[]string{"CWE-328"}, StatusFinalized, []Reference{refRFC6151, refSP800131A}}
	pvWeakCipher = Provenance{[]string{"CWE-327"}, StatusFinalized, []Reference{refSP800131A}}
	pvKeySize    = Provenance{[]string{"CWE-326"}, StatusFinalized, []Reference{refSP80057, refSP800131A}}
	pvCurve      = Provenance{[]string{"CWE-326"}, StatusFinalized, []Reference{refSP80057}}
	pvECB        = Provenance{[]string{"CWE-327"}, StatusFinalized, []Reference{refSP80038A, refOWASPCS}}
	pvStaticIV   = Provenance{[]string{"CWE-329"}, StatusFinalized, []Reference{refSP80038A, refOWASPCS}}
	pvHardcoded  = Provenance{[]string{"CWE-321", "CWE-798"}, StatusGuidance, []Reference{refOWASPSec, refOWASPCS}}
	pvWeakPRNG   = Provenance{[]string{"CWE-338"}, StatusGuidance, []Reference{refSP80090A, refOWASPCS}}
	pvTiming     = Provenance{[]string{"CWE-208"}, StatusGuidance, []Reference{refOWASPCS}}
	pvProtocol   = Provenance{[]string{"CWE-327"}, StatusFinalized, []Reference{refRFC8996, refRFC7568, refSP80052}}
	pvCipherST   = Provenance{[]string{"CWE-327"}, StatusFinalized, []Reference{refSP80052}}
	pvCertSig    = Provenance{[]string{"CWE-328"}, StatusFinalized, []Reference{refSP800131A}}
	pvCertExp    = Provenance{[]string{"CWE-298"}, StatusGuidance, []Reference{refRFC5280}}
	pvPQC        = Provenance{nil, StatusFinalized, []Reference{refFIPS203, refFIPS204, refFIPS205, refCNSA2}}
	pvInvHash    = Provenance{nil, StatusGuidance, []Reference{refSP800131A}}
	pvInvProto   = Provenance{nil, StatusGuidance, []Reference{refSP80052}}
	pvInvKey     = Provenance{nil, StatusGuidance, []Reference{refSP80057}}
	pvInvCert    = Provenance{nil, StatusGuidance, []Reference{refRFC5280}}
)

// catalog maps every emitted rule ID to its provenance. This is the auditable basis
// of the ruleset; tests assert it stays complete and well-formed.
var catalog = map[string]Provenance{
	// Quantum-vulnerable asymmetric crypto.
	"CB-ASYM-RSA-CIPHER": pvQuantum, "CB-ASYM-RSA-KEYGEN": pvQuantum,
	"CB-ASYM-EC-KEYGEN": pvQuantum, "CB-ASYM-DSA-KEYGEN": pvQuantum,
	"CB-ASYM-DH-KEYGEN": pvQuantum, "CB-ASYM-EDDSA-KEYGEN": pvQuantum,
	"CB-ASYM-XDH-KEYGEN": pvQuantum, "CB-ASYM-ED25519": pvQuantum,
	"CB-SIG-RSA": pvQuantum, "CB-SIG-ECDSA": pvQuantum, "CB-SIG-DSA": pvQuantum,
	"CB-KA-ECDH": pvQuantum, "CB-KA-DH": pvQuantum,
	"CB-CERT-KEY-RSA": pvQuantum, "CB-CERT-KEY-EC": pvQuantum,
	"CB-CERT-KEY-ED25519": pvQuantum, "CB-CERT-KEY-DSA": pvQuantum,

	// Weak / deprecated primitives.
	"CB-WEAK-MD5": pvMD5, "CB-WEAK-MD4": pvWeakHash, "CB-WEAK-MD2": pvWeakHash,
	"CB-WEAK-SHA1": pvWeakHash,
	"CB-WEAK-DES":  pvWeakCipher, "CB-WEAK-3DES": pvWeakCipher, "CB-WEAK-RC4": pvWeakCipher,
	"CB-WEAK-RC2": pvWeakCipher, "CB-WEAK-BLOWFISH": pvWeakCipher,
	"CB-WEAK-KEYSIZE": pvKeySize, "CB-WEAK-CURVE": pvCurve,
	"CB-WEAK-CERT-SIG": pvCertSig,

	// Misuse.
	"CB-MISUSE-ECB": pvECB, "CB-MISUSE-STATIC-IV": pvStaticIV,
	"CB-MISUSE-HARDCODED-KEY": pvHardcoded, "CB-MISUSE-WEAK-PRNG": pvWeakPRNG,
	"CB-MISUSE-TIMING-COMPARE": pvTiming,

	// Protocols & cipher suites.
	"CB-WEAK-PROTOCOL": pvProtocol, "CB-WEAK-CIPHERSUITE": pvCipherST,

	// Material.
	"CB-MATERIAL-PRIVATE-KEY": pvHardcoded, "CB-MATERIAL-KEYSTORE": pvHardcoded,
	"CB-CERT-EXPIRED": pvCertExp,

	// Post-quantum (quantum-safe inventory).
	"CB-PQC": pvPQC,

	// Inventory.
	"CB-INV-HASH": pvInvHash, "CB-INV-PROTOCOL": pvInvProto,
	"CB-INV-SYMKEY": pvInvKey, "CB-INV-PUBLIC-KEY": pvInvKey,
	"CB-INV-CERTIFICATE": pvInvCert,
}
