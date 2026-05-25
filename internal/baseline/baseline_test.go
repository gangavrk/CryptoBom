package baseline

import (
	"path/filepath"
	"testing"

	"github.com/cryptobom/cryptobom/internal/rules"
)

func mk(file, rule string, line int) rules.Finding {
	return rules.Finding{Match: rules.Match{RuleID: rule, Algorithm: "MD5"}, File: file, Line: line, Evidence: "md5()"}
}

func TestFingerprintStableAcrossLines(t *testing.T) {
	a := mk("a.py", "CB-WEAK-MD5", 10)
	b := mk("a.py", "CB-WEAK-MD5", 99) // same finding, different line
	if Fingerprint(a) != Fingerprint(b) {
		t.Error("fingerprint must be stable across line-number changes")
	}
	c := mk("b.py", "CB-WEAK-MD5", 10) // different file
	if Fingerprint(a) == Fingerprint(c) {
		t.Error("fingerprint must differ by file")
	}
}

func TestWriteLoadFilter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	existing := []rules.Finding{mk("a.py", "CB-WEAK-MD5", 10)}
	if _, err := Write(path, existing); err != nil {
		t.Fatal(err)
	}
	set, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	// New scan: the baselined finding (moved to line 12) plus a genuinely new one.
	scan := []rules.Finding{mk("a.py", "CB-WEAK-MD5", 12), mk("a.py", "CB-WEAK-SHA1", 20)}
	got := Filter(scan, set)
	if len(got) != 1 || got[0].RuleID != "CB-WEAK-SHA1" {
		t.Errorf("Filter: expected only the new SHA-1 finding, got %d: %+v", len(got), got)
	}
}
