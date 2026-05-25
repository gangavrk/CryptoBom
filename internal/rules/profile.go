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
// introduce false positives. Profiles are defined in rulepack.yaml; the policy
// is a category→status table, so the differences between standards are visible
// at a glance (the key one being how each treats quantum-vulnerable crypto).
type Profile struct {
	ID        string
	Name      string
	Summary   string
	Reference Reference
	policy    map[Category]policyEntry
}

// Classify reports the finding's status under the profile and, for violations,
// an optional severity the standard assigns (empty = keep the finding's base
// severity). A category absent from the policy is treated as not-applicable.
func (p *Profile) Classify(m Match) (Compliance, Severity) {
	e, ok := p.policy[m.Category]
	if !ok {
		return ComplianceNotApplicable, ""
	}
	return e.Status, e.Severity
}

// profiles is built once from the loaded rule-pack, resolving each profile's
// citation key against the shared reference list.
var profiles = buildProfiles()

func buildProfiles() map[string]*Profile {
	out := make(map[string]*Profile, len(pack.Profiles))
	for id, def := range pack.Profiles {
		out[id] = &Profile{
			ID:        id,
			Name:      def.Name,
			Summary:   def.Summary,
			Reference: pack.References[def.Reference],
			policy:    def.Policy,
		}
	}
	return out
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
		status, sev := p.Classify(findings[i].Match)
		findings[i].Compliance = status
		if status == ComplianceViolation && sev != "" {
			findings[i].Severity = sev
		}
	}
}
