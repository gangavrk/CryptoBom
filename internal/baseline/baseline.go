// Package baseline records a set of known findings so that subsequent scans can
// surface only new ones. Fingerprints deliberately exclude line/column so that
// findings survive unrelated edits that shift line numbers.
package baseline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"

	"github.com/cryptobom/cryptobom/internal/rules"
)

type entry struct {
	Fingerprint string `json:"fingerprint"`
	Rule        string `json:"rule"`
	File        string `json:"file"`
}

type document struct {
	Version  int     `json:"version"`
	Findings []entry `json:"findings"`
}

// Fingerprint is a stable identity for a finding (independent of its line number).
func Fingerprint(f rules.Finding) string {
	parts := f.File + "\x00" + f.RuleID + "\x00" + f.Algorithm + "\x00" +
		f.Mode + "\x00" + f.Detail + "\x00" + f.Evidence + "\x00" + f.Scope
	sum := sha256.Sum256([]byte(parts))
	return hex.EncodeToString(sum[:])
}

// Set is a loaded baseline.
type Set struct{ m map[string]bool }

// Load reads a baseline file.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	s := &Set{m: make(map[string]bool, len(doc.Findings))}
	for _, e := range doc.Findings {
		s.m[e.Fingerprint] = true
	}
	return s, nil
}

// Filter returns the findings not present in the baseline.
func Filter(findings []rules.Finding, s *Set) []rules.Finding {
	out := findings[:0]
	for _, f := range findings {
		if !s.m[Fingerprint(f)] {
			out = append(out, f)
		}
	}
	return out
}

// Write records the given findings as a baseline file and returns how many unique
// findings were written.
func Write(path string, findings []rules.Finding) (int, error) {
	doc := document{Version: 1}
	seen := map[string]bool{}
	for _, f := range findings {
		fp := Fingerprint(f)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		doc.Findings = append(doc.Findings, entry{Fingerprint: fp, Rule: f.RuleID, File: f.File})
	}
	sort.Slice(doc.Findings, func(i, j int) bool { return doc.Findings[i].Fingerprint < doc.Findings[j].Fingerprint })
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return 0, err
	}
	return len(doc.Findings), os.WriteFile(path, append(data, '\n'), 0o644)
}
