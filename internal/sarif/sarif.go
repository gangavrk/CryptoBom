// Package sarif renders findings as SARIF 2.1.0 for IDE and CI integration
// (e.g. GitHub code scanning). Only actionable problems are emitted; inventory
// (info) findings belong in the CBOM, not in a results list meant for triage.
package sarif

import (
	"encoding/json"
	"io"
	"sort"

	"github.com/cryptobom/cryptobom/internal/rules"
	"github.com/cryptobom/cryptobom/internal/version"
)

const (
	schemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	toolName  = "cryptobom"
)

type document struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name    string                `json:"name"`
	Version string                `json:"version"`
	Rules   []reportingDescriptor `json:"rules"`
}

type reportingDescriptor struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	ShortDescription text           `json:"shortDescription"`
	FullDescription  *text          `json:"fullDescription,omitempty"`
	DefaultConfig    configuration  `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties,omitempty"`
}

type configuration struct {
	Level string `json:"level"`
}

type text struct {
	Text string `json:"text"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Level     string     `json:"level"`
	Message   text       `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine   int   `json:"startLine"`
	StartColumn int   `json:"startColumn,omitempty"`
	Snippet     *text `json:"snippet,omitempty"`
}

// Emit writes a SARIF 2.1.0 report for findings to w.
func Emit(w io.Writer, findings []rules.Finding) error {
	doc := build(findings)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

func build(findings []rules.Finding) document {
	problems := make([]rules.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Severity != rules.SeverityInfo {
			problems = append(problems, f)
		}
	}
	sort.SliceStable(problems, func(i, j int) bool {
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		if problems[i].Line != problems[j].Line {
			return problems[i].Line < problems[j].Line
		}
		return problems[i].RuleID < problems[j].RuleID
	})

	descriptors, index := descriptorsFor(problems)

	results := make([]result, 0, len(problems))
	for _, f := range problems {
		results = append(results, result{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     level(f.Severity),
			Message:   text{Text: f.Title + " — " + f.Detail},
			Locations: []location{{
				PhysicalLocation: physicalLocation{
					ArtifactLocation: artifactLocation{URI: f.File},
					Region: region{
						StartLine:   f.Line,
						StartColumn: f.Column,
						Snippet:     &text{Text: f.Evidence},
					},
				},
			}},
		})
	}

	return document{
		Schema:  schemaURI,
		Version: "2.1.0",
		Runs: []run{{
			Tool:    tool{Driver: driver{Name: toolName, Version: version.Version, Rules: descriptors}},
			Results: results,
		}},
	}
}

// descriptorsFor builds the deduplicated rule metadata and a rule-id→index map.
func descriptorsFor(problems []rules.Finding) ([]reportingDescriptor, map[string]int) {
	first := map[string]rules.Finding{}
	var ids []string
	for _, f := range problems {
		if _, ok := first[f.RuleID]; !ok {
			first[f.RuleID] = f
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)

	descriptors := make([]reportingDescriptor, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		f := first[id]
		index[id] = i
		d := reportingDescriptor{
			ID:               id,
			Name:             f.RuleID,
			ShortDescription: text{Text: f.Title},
			DefaultConfig:    configuration{Level: level(f.Severity)},
			Properties: map[string]any{
				"category": string(f.Category),
				"tags":     []string{"cryptography", "post-quantum", string(f.Category)},
			},
		}
		if sev := securitySeverity(f.Severity); sev != "" {
			d.Properties["security-severity"] = sev
		}
		if f.Remediation != "" {
			d.FullDescription = &text{Text: f.Remediation}
		}
		descriptors = append(descriptors, d)
	}
	return descriptors, index
}

func level(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return "error"
	case rules.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

// securitySeverity returns a CVSS-like score string used by GitHub code scanning.
func securitySeverity(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "9.5"
	case rules.SeverityHigh:
		return "8.0"
	case rules.SeverityMedium:
		return "5.5"
	case rules.SeverityLow:
		return "3.0"
	}
	return ""
}
