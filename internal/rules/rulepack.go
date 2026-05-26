package rules

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// rulepack.yaml carries the data-only parts of the ruleset: citations, per-rule
// provenance, the rule-pack version, and the compliance profiles. It is embedded
// so the binary stays a single offline artifact, and validated at load.
//
//go:embed rulepack.yaml
var rulepackYAML []byte

// rulepack is the parsed rulepack.yaml.
type rulepack struct {
	Version    string                `yaml:"version"`
	References map[string]Reference  `yaml:"references"`
	Rules      map[string]ruleMeta   `yaml:"rules"`
	OIDs       map[string]string     `yaml:"oids"` // canonical algorithm name -> ASN.1 OID
	Profiles   map[string]profileDef `yaml:"profiles"`
}

// ruleMeta is the per-rule provenance held in the file. cwe is optional.
type ruleMeta struct {
	CWE            []string       `yaml:"cwe"`
	StandardStatus StandardStatus `yaml:"standardStatus"`
	References     []string       `yaml:"references"` // keys into rulepack.References
}

// profileDef is a compliance profile as written in the file.
type profileDef struct {
	Name      string                   `yaml:"name"`
	Summary   string                   `yaml:"summary"`
	Reference string                   `yaml:"reference"` // key into rulepack.References
	Policy    map[Category]policyEntry `yaml:"policy"`
}

// policyEntry maps a finding category to its compliance status under a profile.
// Severity is an optional override applied to violations the standard regards
// more severely than the base rule (empty = keep the finding's base severity).
type policyEntry struct {
	Status   Compliance `yaml:"status"`
	Severity Severity   `yaml:"severity"`
}

// pack is the loaded, validated rulepack. The file is embedded and build-tested,
// so a failure here is a programming error: panic, and the rulepack tests catch
// it before anything ships.
var pack = mustLoad()

func mustLoad() rulepack {
	var p rulepack
	if err := yaml.Unmarshal(rulepackYAML, &p); err != nil {
		panic(fmt.Sprintf("rulepack: parse: %v", err))
	}
	if err := p.validate(); err != nil {
		panic(fmt.Sprintf("rulepack: %v", err))
	}
	return p
}

// validate enforces the invariants the rest of the package relies on: a version,
// well-formed references, complete per-rule provenance, and coherent profiles.
func (p rulepack) validate() error {
	if p.Version == "" {
		return fmt.Errorf("missing version")
	}
	for key, r := range p.References {
		if r.Authority == "" || r.ID == "" || !hasHTTPS(r.URL) {
			return fmt.Errorf("reference %q is malformed: %+v", key, r)
		}
	}
	for id, r := range p.Rules {
		switch r.StandardStatus {
		case StatusFinalized, StatusDraft, StatusGuidance:
		default:
			return fmt.Errorf("rule %s: invalid standardStatus %q", id, r.StandardStatus)
		}
		if len(r.References) == 0 {
			return fmt.Errorf("rule %s: no references", id)
		}
		for _, ref := range r.References {
			if _, ok := p.References[ref]; !ok {
				return fmt.Errorf("rule %s: unknown reference %q", id, ref)
			}
		}
	}
	for alg, oid := range p.OIDs {
		if alg == "" {
			return fmt.Errorf("oids: empty algorithm key")
		}
		if !isOID(oid) {
			return fmt.Errorf("oids[%s]: malformed OID %q", alg, oid)
		}
	}
	for id, prof := range p.Profiles {
		if prof.Name == "" {
			return fmt.Errorf("profile %s: missing name", id)
		}
		if _, ok := p.References[prof.Reference]; !ok {
			return fmt.Errorf("profile %s: unknown reference %q", id, prof.Reference)
		}
		if len(prof.Policy) == 0 {
			return fmt.Errorf("profile %s: empty policy", id)
		}
		for cat, e := range prof.Policy {
			switch e.Status {
			case ComplianceViolation, ComplianceNotApplicable, ComplianceCompliant:
			default:
				return fmt.Errorf("profile %s: category %q has invalid status %q", id, cat, e.Status)
			}
			if e.Severity != "" && !sevValid(e.Severity) {
				return fmt.Errorf("profile %s: category %q has invalid severity %q", id, cat, e.Severity)
			}
		}
	}
	return nil
}

// OIDFor returns the ASN.1 object identifier for a canonical algorithm name, or
// "" if none is recorded. Only unambiguous algorithm-level OIDs are mapped; a
// missing entry means "don't assert an OID" rather than a guess.
func OIDFor(algorithm string) string { return pack.OIDs[algorithm] }

func hasHTTPS(s string) bool { return len(s) >= 8 && s[:8] == "https://" }

// isOID reports whether s is a well-formed dotted-decimal object identifier
// (at least two numeric arcs, no empty arcs).
func isOID(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func sevValid(s Severity) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}
