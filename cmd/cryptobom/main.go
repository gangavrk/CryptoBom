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

	csharpanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/csharp"
	golanganalyzer "github.com/cryptobom/cryptobom/internal/analyzers/golang"
	javaanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/java"
	kotlinanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/kotlin"
	pythonanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/python"
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
  --format string   stdout format: terminal | cbom | sarif  (default "terminal")
  --cbom file       also write a CycloneDX CBOM to file
  --sarif file      also write a SARIF 2.1.0 report to file
  --no-color        disable ANSI colors in terminal output

The --cbom and --sarif flags write to files independently of --format, so a
single scan can print a developer report and emit both machine artifacts:

  cryptobom scan --sarif results.sarif --cbom cbom.json ./src

path defaults to the current directory.
`

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true,
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "cryptobom: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Print(usage)
		return nil
	}
	if args[0] == "version" || args[0] == "--version" || args[0] == "-v" {
		fmt.Printf("cryptobom %s\n", version.Version)
		return nil
	}
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q (try 'scan')", args[0])
	}

	format := "terminal"
	noColor := false
	var path, cbomPath, sarifPath string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		var err error
		switch {
		case a == "--no-color":
			noColor = true
		case a == "--format" || strings.HasPrefix(a, "--format="):
			format, i, err = flagValue("--format", rest, i)
		case a == "--cbom" || strings.HasPrefix(a, "--cbom="):
			cbomPath, i, err = flagValue("--cbom", rest, i)
		case a == "--sarif" || strings.HasPrefix(a, "--sarif="):
			sarifPath, i, err = flagValue("--sarif", rest, i)
		case strings.HasPrefix(a, "-"):
			err = fmt.Errorf("unknown flag %q", a)
		default:
			path = a
		}
		if err != nil {
			return err
		}
	}
	if path == "" {
		path = "."
	}
	if format != "terminal" && format != "cbom" && format != "sarif" {
		return fmt.Errorf("invalid --format %q (want terminal, cbom, or sarif)", format)
	}

	findings, err := scan(path)
	if err != nil {
		return err
	}

	// File outputs are written independently of the stdout --format.
	if cbomPath != "" {
		if err := emitToFile(cbomPath, func(w io.Writer) error { return cbom.Emit(w, path, findings) }); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "cryptobom: wrote CBOM to %s\n", cbomPath)
	}
	if sarifPath != "" {
		if err := emitToFile(sarifPath, func(w io.Writer) error { return sarif.Emit(w, findings) }); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "cryptobom: wrote SARIF to %s\n", sarifPath)
	}

	switch format {
	case "cbom":
		return cbom.Emit(os.Stdout, path, findings)
	case "sarif":
		return sarif.Emit(os.Stdout, findings)
	default:
		report.Write(os.Stdout, path, findings, !noColor && isTerminal(os.Stdout))
		return nil
	}
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

// scan walks path for supported source files and aggregates findings.
func scan(path string) ([]rules.Finding, error) {
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
			return nil
		}
		if !supported(d.Name()) {
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

func supported(name string) bool {
	return strings.HasSuffix(name, ".java") ||
		strings.HasSuffix(name, ".py") ||
		strings.HasSuffix(name, ".go") ||
		strings.HasSuffix(name, ".kt") ||
		strings.HasSuffix(name, ".kts") ||
		strings.HasSuffix(name, ".cs")
}

// analyzeFile dispatches to the analyzer for the file's language.
func analyzeFile(p string) ([]rules.Finding, error) {
	src, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	switch {
	case strings.HasSuffix(p, ".java"):
		return javaanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".py"):
		return pythonanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".go"):
		return golanganalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".kt"), strings.HasSuffix(p, ".kts"):
		return kotlinanalyzer.Analyze(p, src)
	case strings.HasSuffix(p, ".cs"):
		return csharpanalyzer.Analyze(p, src)
	}
	return nil, nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
