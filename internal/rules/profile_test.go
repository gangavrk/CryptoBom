package rules

import "testing"

func TestProfileByID(t *testing.T) {
	for _, id := range []string{"cnsa-2.0", "fips-140-3", "dora"} {
		if _, ok := ProfileByID(id); !ok {
			t.Errorf("ProfileByID(%q) = not found, want found", id)
		}
	}
	// Case-insensitive and whitespace-trimmed.
	if _, ok := ProfileByID("  CNSA-2.0 "); !ok {
		t.Errorf("ProfileByID is not case/space tolerant")
	}
	if _, ok := ProfileByID("bogus"); ok {
		t.Errorf("ProfileByID(bogus) = found, want not found")
	}
}

func TestProfileIDs(t *testing.T) {
	ids := ProfileIDs()
	want := []string{"cnsa-2.0", "dora", "fips-140-3"} // sorted
	if len(ids) != len(want) {
		t.Fatalf("ProfileIDs() = %v, want %v", ids, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("ProfileIDs() = %v, want %v", ids, want)
		}
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name       string
		profile    string
		category   Category
		wantStatus Compliance
		wantSev    Severity // "" = no override (keep base)
	}{
		// The defining distinction: quantum-vulnerable crypto is a must-fix under
		// CNSA 2.0 (elevated to critical) but still permitted under FIPS/DORA.
		{"cnsa quantum-vuln", "cnsa-2.0", CategoryQuantumVulnerable, ComplianceViolation, SeverityCritical},
		{"fips quantum-vuln", "fips-140-3", CategoryQuantumVulnerable, ComplianceNotApplicable, ""},
		{"dora quantum-vuln", "dora", CategoryQuantumVulnerable, ComplianceNotApplicable, ""},

		// Weak/deprecated and misuse breach every standard.
		{"cnsa weak", "cnsa-2.0", CategoryWeak, ComplianceViolation, ""},
		{"fips weak", "fips-140-3", CategoryWeak, ComplianceViolation, ""},
		{"dora weak", "dora", CategoryWeak, ComplianceViolation, ""},
		{"cnsa misuse", "cnsa-2.0", CategoryMisuse, ComplianceViolation, ""},
		{"fips misuse", "fips-140-3", CategoryMisuse, ComplianceViolation, ""},
		{"dora misuse", "dora", CategoryMisuse, ComplianceViolation, ""},

		// PQC in use is a positive; inventory is out of scope.
		{"cnsa pqc", "cnsa-2.0", CategoryQuantumSafe, ComplianceCompliant, ""},
		{"fips pqc", "fips-140-3", CategoryQuantumSafe, ComplianceCompliant, ""},
		{"cnsa inventory", "cnsa-2.0", CategoryInventory, ComplianceNotApplicable, ""},
		{"fips inventory", "fips-140-3", CategoryInventory, ComplianceNotApplicable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := ProfileByID(tc.profile)
			if !ok {
				t.Fatalf("unknown profile %q", tc.profile)
			}
			status, sev := p.Classify(Match{Category: tc.category, Severity: SeverityHigh})
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if sev != tc.wantSev {
				t.Errorf("severity override = %q, want %q", sev, tc.wantSev)
			}
		})
	}
}

func TestApplyProfile(t *testing.T) {
	cnsa, _ := ProfileByID("cnsa-2.0")
	fips, _ := ProfileByID("fips-140-3")

	// CNSA elevates a quantum-vulnerable finding to critical and marks it a violation.
	qv := []Finding{{Match: Match{Category: CategoryQuantumVulnerable, Severity: SeverityHigh}}}
	ApplyProfile(qv, cnsa)
	if qv[0].Compliance != ComplianceViolation {
		t.Errorf("CNSA quantum-vuln compliance = %q, want violation", qv[0].Compliance)
	}
	if qv[0].Severity != SeverityCritical {
		t.Errorf("CNSA quantum-vuln severity = %q, want critical", qv[0].Severity)
	}

	// FIPS leaves the same finding's severity untouched and marks it not-applicable.
	qv2 := []Finding{{Match: Match{Category: CategoryQuantumVulnerable, Severity: SeverityHigh}}}
	ApplyProfile(qv2, fips)
	if qv2[0].Compliance != ComplianceNotApplicable {
		t.Errorf("FIPS quantum-vuln compliance = %q, want not-applicable", qv2[0].Compliance)
	}
	if qv2[0].Severity != SeverityHigh {
		t.Errorf("FIPS quantum-vuln severity = %q, want high (unchanged)", qv2[0].Severity)
	}
}

// TestApplyProfileTagsEveryFinding guards that the classifier handles every
// category for every profile — no finding is ever left without a status.
func TestApplyProfileTagsEveryFinding(t *testing.T) {
	cats := []Category{
		CategoryQuantumVulnerable, CategoryWeak, CategoryMisuse,
		CategoryInventory, CategoryQuantumSafe,
	}
	for _, id := range ProfileIDs() {
		p, _ := ProfileByID(id)
		findings := make([]Finding, len(cats))
		for i, c := range cats {
			findings[i] = Finding{Match: Match{Category: c, Severity: SeverityMedium}}
		}
		ApplyProfile(findings, p)
		for i, f := range findings {
			if f.Compliance == "" {
				t.Errorf("profile %q left category %q unclassified", id, cats[i])
			}
		}
	}
}
