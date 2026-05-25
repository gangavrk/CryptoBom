// Command cryptobom scans source code for cryptographic usage and reports
// quantum-vulnerable, weak, and misused algorithms as a terminal report, a
// CycloneDX CBOM, and/or a SARIF report.
package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	cfamilyanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/cfamily"
	configanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/config"
	csharpanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/csharp"
	golanganalyzer "github.com/cryptobom/cryptobom/internal/analyzers/golang"
	javaanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/java"
	jsanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/javascript"
	kotlinanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/kotlin"
	materialanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/material"
	pythonanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/python"
	"github.com/cryptobom/cryptobom/internal/baseline"
	"github.com/cryptobom/cryptobom/internal/cbom"
	"github.com/cryptobom/cryptobom/internal/report"
	"github.com/cryptobom/cryptobom/internal/rules"
	"github.com/cryptobom/cryptobom/internal/sarif"
	"github.com/cryptobom/cryptobom/internal/version"
)

const usage = `cryptobom — cryptographic discovery for the post-quantum transition

usage:
  cryptobom scan [flags] [path]
  cryptobom version

flags:
  --format string        stdout format: terminal | cbom | sarif  (default "terminal")
  --cbom file            also write a CycloneDX CBOM to file
  --sarif file           also write a SARIF 2.1.0 report to file
  --fail-on severity     exit non-zero (code 2) if a finding is >= this severity
                         (critical | high | medium | low)
  --baseline file        ignore findings recorded in the baseline (surface only new)
  --write-baseline file  write the current findings to a baseline file and exit
  --include-tests        also scan test code (test/ dirs, *_test.go, *Test.java, …)
  --no-color             disable ANSI colors in terminal output

Findings can be suppressed inline with a "cryptobom:ignore" comment (optionally
"cryptobom:ignore[CB-WEAK-MD5]") on the finding's line or the line above it.

The --cbom and --sarif flags write to files independently of --format, so a
single scan can print a developer report and emit both machine artifacts:

  cryptobom scan --sarif results.sarif --cbom cbom.json ./src

path defaults to the current directory.
`

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
}

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "cryptobom: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

// run executes the CLI and returns a process exit code (0 ok, 2 = --fail-on
// threshold met) plus an operational error (mapped to exit 1 by main).
func run(args []string) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return 0, nil
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		fmt.Printf("cryptobom %s\n", version.Version)
		return 0, nil
	}
	if args[0] != "scan" {
		return 0, fmt.Errorf("unknown command %q (try 'scan')", args[0])
	}

	format := "terminal"
	noColor := false
	includeTests := false
	var path, cbomPath, sarifPath, failOn, baselinePath, writeBaselinePath string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		var err error
		switch {
		case a == "--no-color":
			noColor = true
		case a == "--include-tests":
			includeTests = true
		case a == "--format" || strings.HasPrefix(a, "--format="):
			format, i, err = flagValue("--format", rest, i)
		case a == "--cbom" || strings.HasPrefix(a, "--cbom="):
			cbomPath, i, err = flagValue("--cbom", rest, i)
		case a == "--sarif" || strings.HasPrefix(a, "--sarif="):
			sarifPath, i, err = flagValue("--sarif", rest, i)
		case a == "--fail-on" || strings.HasPrefix(a, "--fail-on="):
			failOn, i, err = flagValue("--fail-on", rest, i)
		case a == "--baseline" || strings.HasPrefix(a, "--baseline="):
			baselinePath, i, err = flagValue("--baseline", rest, i)
		case a == "--write-baseline" || strings.HasPrefix(a, "--write-baseline="):
			writeBaselinePath, i, err = flagValue("--write-baseline", rest, i)
		case strings.HasPrefix(a, "-"):
			err = fmt.Errorf("unknown flag %q", a)
		default:
			path = a
		}
		if err != nil {
			return 0, err
		}
	}
	if path == "" {
		path = "."
	}
	if format != "terminal" && format != "cbom" && format != "sarif" {
		return 0, fmt.Errorf("invalid --format %q (want terminal, cbom, or sarif)", format)
	}
	if failOn != "" && sevRank(rules.Severity(failOn)) == 0 {
		return 0, fmt.Errorf("invalid --fail-on %q (want critical, high, medium, or low)", failOn)
	}

	findings, err := scan(path, includeTests)
	if err != nil {
		return 0, err
	}

	if writeBaselinePath != "" {
		n, werr := baseline.Write(writeBaselinePath, findings)
		if werr != nil {
			return 0, werr
		}
		fmt.Fprintf(os.Stderr, "cryptobom: wrote baseline (%d findings) to %s\n", n, writeBaselinePath)
		return 0, nil
	}
	if baselinePath != "" {
		set, lerr := baseline.Load(baselinePath)
		if lerr != nil {
			return 0, fmt.Errorf("baseline: %w", lerr)
		}
		findings = baseline.Filter(findings, set)
	}

	// File outputs are written independently of the stdout --format.
	if cbomPath != "" {
		if err := emitToFile(cbomPath, func(w io.Writer) error { return cbom.Emit(w, path, findings) }); err != nil {
			return 0, err
		}
		fmt.Fprintf(os.Stderr, "cryptobom: wrote CBOM to %s\n", cbomPath)
	}
	if sarifPath != "" {
		if err := emitToFile(sarifPath, func(w io.Writer) error { return sarif.Emit(w, findings) }); err != nil {
			return 0, err
		}
		fmt.Fprintf(os.Stderr, "cryptobom: wrote SARIF to %s\n", sarifPath)
	}

	switch format {
	case "cbom":
		if err := cbom.Emit(os.Stdout, path, findings); err != nil {
			return 0, err
		}
	case "sarif":
		if err := sarif.Emit(os.Stdout, findings); err != nil {
			return 0, err
		}
	default:
		report.Write(os.Stdout, path, findings, !noColor && isTerminal(os.Stdout))
	}

	if failOn != "" && anyAtOrAbove(findings, rules.Severity(failOn)) {
		return 2, nil
	}
	return 0, nil
}

// sevRank orders severities (higher = more severe); info is 0 and never gates.
func sevRank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 4
	case rules.SeverityHigh:
		return 3
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 1
	}
	return 0
}

func anyAtOrAbove(findings []rules.Finding, threshold rules.Severity) bool {
	th := sevRank(threshold)
	for _, f := range findings {
		if sevRank(f.Severity) >= th {
			return true
		}
	}
	return false
}

// flagValue resolves a flag's value given as "--flag value" or "--flag=value",
// returning the value and the (possibly advanced) loop index.
func flagValue(name string, rest []string, i int) (string, int, error) {
	if v, ok := strings.CutPrefix(rest[i], name+"="); ok {
		return v, i, nil
	}
	if i+1 >= len(rest) {
		return "", i, fmt.Errorf("%s requires a value", name)
	}
	return rest[i+1], i + 1, nil
}

// emitToFile creates path and writes one format to it.
func emitToFile(path string, emit func(io.Writer) error) (err error) {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	return emit(f)
}

// scan walks path for supported source files and aggregates findings. Test code is
// skipped unless includeTests is set; the path given on the command line is always
// scanned (so pointing directly at a test dir/file still works).
func scan(path string, includeTests bool) ([]rules.Finding, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return analyzeFile(path)
	}

	var all []rules.Finding
	err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return fs.SkipDir
			}
			if !includeTests && p != path && isTestDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if !supported(d.Name()) {
			return nil
		}
		if !includeTests && isTestFile(d.Name()) {
			return nil
		}
		fs, ferr := analyzeFile(p)
		if ferr != nil {
			return ferr
		}
		all = append(all, fs...)
		return nil
	})
	return all, err
}

// isTestDir reports whether a directory name is a conventional test location.
func isTestDir(name string) bool {
	switch name {
	case "test", "tests", "testdata", "__tests__":
		return true
	}
	return false
}

// isTestFile reports whether a file name matches a conventional test naming pattern.
func isTestFile(name string) bool {
	base := name
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		base = name[:i]
	}
	switch {
	case strings.HasSuffix(name, "_test.go"): // Go
		return true
	case name == "conftest.py" || strings.HasPrefix(name, "test_") && strings.HasSuffix(name, ".py"): // Python
		return true
	case strings.HasSuffix(name, "_test.py"):
		return true
	case strings.Contains(name, ".test.") || strings.Contains(name, ".spec."): // JS/TS
		return true
	case strings.HasSuffix(base, "Test") || strings.HasSuffix(base, "Tests"): // Java/Kotlin/C#
		return true
	}
	return false
}

func supported(name string) bool {
	return strings.HasSuffix(name, ".java") ||
		strings.HasSuffix(name, ".py") ||
		strings.HasSuffix(name, ".go") ||
		strings.HasSuffix(name, ".kt") ||
		strings.HasSuffix(name, ".kts") ||
		strings.HasSuffix(name, ".cs") ||
		strings.HasSuffix(name, ".js") ||
		strings.HasSuffix(name, ".mjs") ||
		strings.HasSuffix(name, ".cjs") ||
		strings.HasSuffix(name, ".jsx") ||
		strings.HasSuffix(name, ".ts") ||
		strings.HasSuffix(name, ".tsx") ||
		strings.HasSuffix(name, ".c") ||
		strings.HasSuffix(name, ".h") ||
		strings.HasSuffix(name, ".cpp") ||
		strings.HasSuffix(name, ".cc") ||
		strings.HasSuffix(name, ".cxx") ||
		strings.HasSuffix(name, ".hpp") ||
		strings.HasSuffix(name, ".hh") ||
		strings.HasSuffix(name, ".properties") ||
		strings.HasSuffix(name, ".yml") ||
		strings.HasSuffix(name, ".yaml") ||
		strings.HasSuffix(name, ".conf") ||
		materialanalyzer.IsMaterialFile(name)
}

// analyzeFile dispatches to the analyzer for the file's language and tags findings
// from test code with the "test" scope.
func analyzeFile(p string) ([]rules.Finding, error) {
	src, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var findings []rules.Finding
	switch {
	case strings.HasSuffix(p, ".java"):
		findings, err = javaanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".py"):
		findings, err = pythonanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".go"):
		findings, err = golanganalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".kt"), strings.HasSuffix(p, ".kts"):
		findings, err = kotlinanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".cs"):
		findings, err = csharpanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".mjs"), strings.HasSuffix(p, ".cjs"),
		strings.HasSuffix(p, ".jsx"), strings.HasSuffix(p, ".ts"), strings.HasSuffix(p, ".tsx"):
		findings, err = jsanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".c"), strings.HasSuffix(p, ".h"), strings.HasSuffix(p, ".cpp"),
		strings.HasSuffix(p, ".cc"), strings.HasSuffix(p, ".cxx"), strings.HasSuffix(p, ".hpp"),
		strings.HasSuffix(p, ".hh"):
		findings, err = cfamilyanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".properties"),
		strings.HasSuffix(p, ".yml"), strings.HasSuffix(p, ".yaml"), strings.HasSuffix(p, ".conf"):
		findings, err = configanalyzer.Analyze(p, src)
	case materialanalyzer.IsMaterialFile(filepath.Base(p)):
		findings, err = materialanalyzer.Analyze(p, src)
	}
	if err == nil {
		findings = applySuppressions(findings, src)
		if isTestPath(p) {
			for i := range findings {
				findings[i].Scope = "test"
			}
		}
	}
	return findings, err
}

// applySuppressions drops findings whose line (or the line above) carries a
// "cryptobom:ignore" comment.
func applySuppressions(findings []rules.Finding, src []byte) []rules.Finding {
	if len(findings) == 0 {
		return findings
	}
	lines := strings.Split(string(src), "\n")
	out := findings[:0]
	for _, f := range findings {
		if suppressed(lines, f.Line, f.RuleID) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func suppressed(lines []string, line int, ruleID string) bool {
	// The finding's own line: a trailing or standalone marker both apply.
	if idx := line - 1; idx >= 0 && idx < len(lines) && markerApplies(lines[idx], ruleID, false) {
		return true
	}
	// The line above: only a comment-only marker applies, so a trailing ignore on
	// one line doesn't leak onto the next.
	if idx := line - 2; idx >= 0 && idx < len(lines) && markerApplies(lines[idx], ruleID, true) {
		return true
	}
	return false
}

// markerApplies reports whether a cryptobom:ignore marker on line suppresses ruleID.
// "cryptobom:ignore" alone suppresses any rule; "cryptobom:ignore[CB-X,CB-Y]"
// suppresses only the listed rules. When requireCommentOnly is set, the marker must
// be the only content on the line (apart from whitespace/comment punctuation).
func markerApplies(line, ruleID string, requireCommentOnly bool) bool {
	const marker = "cryptobom:ignore"
	i := strings.Index(line, marker)
	if i < 0 {
		return false
	}
	if requireCommentOnly && strings.TrimLeft(line[:i], " \t/#*-!<") != "" {
		return false
	}
	rest := line[i+len(marker):]
	if !strings.HasPrefix(rest, "[") {
		return true // bare marker → all rules
	}
	end := strings.Index(rest, "]")
	if end < 0 {
		return true
	}
	for _, r := range strings.Split(rest[1:end], ",") {
		if strings.TrimSpace(r) == ruleID {
			return true
		}
	}
	return false
}

// isTestPath reports whether a file path is test code — either a test directory
// segment or a test file name.
func isTestPath(p string) bool {
	segs := strings.Split(filepath.ToSlash(p), "/")
	for _, s := range segs[:len(segs)-1] {
		if isTestDir(s) {
			return true
		}
	}
	return isTestFile(filepath.Base(p))
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
