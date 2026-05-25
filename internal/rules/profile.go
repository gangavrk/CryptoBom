package rules

import (
	"sort"
	"strings"
)

// Compliance is a finding's status under an active compliance profile.
type Compliance string

const (
	// ComplianceViolation: the finding breaches the standard.
	ComplianceViolation Compliance = "violation"
	// ComplianceNotApplicable: the finding is a real weakness, but this standard
	// does not treat it as a breach (e.g. classical RSA under FIPS 140-3).
	ComplianceNotApplicable Compliance = "not-applicable"
	// ComplianceCompliant: a positive signal the standard wants (e.g. PQC in use).
	ComplianceCompliant Compliance = "compliant"
)

// Profile maps cryptobom findings onto the requirements of a named standard,
// classifying each as a violation, not-applicable, or compliant. It is a lens
// over already-detected findings: it adds no detection of its own, so it cannot
// introduce false positives. The differences between profiles reduce to how each
// treats quantum-vulnerable public-key crypto — CNSA 2.0 mandates migration to
// PQC, while FIPS 140-3 and DORA still permit classical RSA/ECDSA today.
type Profile struct {
	ID        string
	Name      string
	Summary   string
	Reference Reference
	classify  func(Match) (Compliance, Severity)
}

// Classify reports the finding's status under the profile and, for violations,
// an optional severity the standard assigns (empty = keep the finding's base
// severity).
func (p *Profile) Classify(m Match) (Compliance, Severity) { return p.classify(m) }

// classifyCommon is the shared policy: weak/deprecated primitives and crypto
// misuse breach every supported standard; post-quantum algorithms in use are a
// positive; everything inventoried but unflagged is out of scope. Profiles differ
// only in how they treat quantum-vulnerable public-key crypto, passed in as qv.
func classifyCommon(m Match, qv Compliance) (Compliance, Severity) {
	switch m.Category {
	case CategoryQuantumSafe:
		return ComplianceCompliant, ""
	case CategoryWeak, CategoryMisuse:
		return ComplianceViolation, ""
	case CategoryQuantumVulnerable:
		// A standard that mandates PQC treats classical public-key crypto as a
		// must-fix: surface it at critical regardless of its base severity.
		if qv == ComplianceViolation {
			return ComplianceViolation, SeverityCritical
		}
		return qv, ""
	default: // CategoryInventory and anything else
		return ComplianceNotApplicable, ""
	}
}

var (
	refFIPS1403 = Reference{"NIST", "FIPS 140-3", "https://csrc.nist.gov/pubs/fips/140-3/final"}
	refDORA     = Reference{"EU", "DORA (Regulation 2022/2554)", "https://eur-lex.europa.eu/eli/reg/2022/2554/oj"}
)

var (
	profileCNSA = &Profile{
		ID:   "cnsa-2.0",
		Name: "NSA CNSA 2.0",
		Summary: "Quantum-vulnerable public-key crypto (RSA, ECDSA, ECDH, DH, EdDSA) must " +
			"migrate to NIST PQC (ML-KEM/ML-DSA/SLH-DSA); weak/deprecated algorithms and misuse are violations.",
		Reference: refCNSA2,
		classify:  func(m Match) (Compliance, Severity) { return classifyCommon(m, ComplianceViolation) },
	}
	profileFIPS = &Profile{
		ID:   "fips-140-3",
		Name: "FIPS 140-3",
		Summary: "Only FIPS-approved algorithms are permitted: classical RSA/ECDSA remain approved " +
			"(reported as not-applicable, not violations), while non-approved/legacy primitives, " +
			"undersized keys, weak protocols, and misuse are violations.",
		Reference: refFIPS1403,
		classify:  func(m Match) (Compliance, Severity) { return classifyCommon(m, ComplianceNotApplicable) },
	}
	profileDORA = &Profile{
		ID:   "dora",
		Name: "EU DORA",
		Summary: "ICT risk management requires sound, current cryptography: broken/deprecated " +
			"algorithms, weak protocols, and misuse are violations. Quantum-vulnerable crypto is " +
			"reported as a risk but not yet a mandated violation.",
		Reference: refDORA,
		classify:  func(m Match) (Compliance, Severity) { return classifyCommon(m, ComplianceNotApplicable) },
	}
)

var profiles = map[string]*Profile{
	profileCNSA.ID: profileCNSA,
	profileFIPS.ID: profileFIPS,
	profileDORA.ID: profileDORA,
}

// ProfileByID returns the profile for an id (case-insensitive).
func ProfileByID(id string) (*Profile, bool) {
	p, ok := profiles[strings.ToLower(strings.TrimSpace(id))]
	return p, ok
}

// ProfileIDs returns the known profile ids, sorted.
func ProfileIDs() []string {
	ids := make([]string, 0, len(profiles))
	for id := range profiles {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// ApplyProfile annotates each finding with its compliance status under p and,
// for violations the standard regards more severely than the base rule, raises
// the finding's severity. Findings are mutated in place. Detection is unchanged;
// this is purely a classification pass.
func ApplyProfile(findings []Finding, p *Profile) {
	for i := range findings {
		status, sev := p.classify(findings[i].Match)
		findings[i].Compliance = status
		if status == ComplianceViolation && sev != "" {
			findings[i].Severity = sev
		}
	}
}
