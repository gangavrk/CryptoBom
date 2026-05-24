// Command cryptobom scans source code for cryptographic usage and reports
// quantum-vulnerable, weak, and misused algorithms as a CycloneDX CBOM or a
// terminal report.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	javaanalyzer "github.com/cryptobom/cryptobom/internal/analyzers/java"
	"github.com/cryptobom/cryptobom/internal/cbom"
	"github.com/cryptobom/cryptobom/internal/report"
	"github.com/cryptobom/cryptobom/internal/rules"
)

const usage = `cryptobom — cryptographic discovery for the post-quantum transition

usage:
  cryptobom scan [flags] [path]

flags:
  --format string   output format: terminal | cbom  (default "terminal")
  --no-color        disable ANSI colors in terminal output

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
	if args[0] != "scan" {
		return fmt.Errorf("unknown command %q (try 'scan')", args[0])
	}

	format := "terminal"
	noColor := false
	var path string
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		switch {
		case a == "--no-color":
			noColor = true
		case a == "--format":
			if i+1 >= len(rest) {
				return fmt.Errorf("--format requires a value (terminal or cbom)")
			}
			i++
			format = rest[i]
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			path = a
		}
	}
	if path == "" {
		path = "."
	}
	if format != "terminal" && format != "cbom" {
		return fmt.Errorf("invalid --format %q (want terminal or cbom)", format)
	}

	findings, err := scan(path)
	if err != nil {
		return err
	}

	switch format {
	case "cbom":
		return cbom.Emit(os.Stdout, path, findings)
	default:
		report.Write(os.Stdout, path, findings, !noColor && isTerminal(os.Stdout))
		return nil
	}
}

// scan walks path for .java files and aggregates findings.
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
		if !strings.HasSuffix(d.Name(), ".java") {
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

func analyzeFile(p string) ([]rules.Finding, error) {
	src, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	return javaanalyzer.Analyze(p, src)
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
