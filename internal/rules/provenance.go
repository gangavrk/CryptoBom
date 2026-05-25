package rules

// RulePackVersion identifies the version of the detection-rule catalog. It is
// stamped into every report so a finding can be traced to the exact ruleset that
// produced it. The value lives in rulepack.yaml (loaded at init).
var RulePackVersion = pack.Version

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
	Authority string `yaml:"authority"` // NIST, NSA, IETF, OWASP, MITRE, EU
	ID        string `yaml:"id"`        // FIPS 203, SP 800-131A Rev.2, RFC 8996, …
	URL       string `yaml:"url"`
}

func (r Reference) String() string { return r.Authority + " " + r.ID }

// Provenance is the verifiable basis of a rule: the weakness class (CWE), the
// status of the underlying standard, and the citations that justify the rule.
type Provenance struct {
	CWE        []string
	Status     StandardStatus
	References []Reference
}

// ProvenanceFor returns the provenance recorded for a rule ID, resolving its
// citation keys against the rule-pack's shared reference list.
func ProvenanceFor(ruleID string) (Provenance, bool) {
	r, ok := pack.Rules[ruleID]
	if !ok {
		return Provenance{}, false
	}
	refs := make([]Reference, 0, len(r.References))
	for _, key := range r.References {
		refs = append(refs, pack.References[key])
	}
	return Provenance{CWE: r.CWE, Status: r.StandardStatus, References: refs}, true
}
