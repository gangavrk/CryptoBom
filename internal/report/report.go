// Package report renders findings as a human-readable terminal report.
package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// ANSI codes, only emitted when color is enabled.
const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	blue   = "\033[34m"
	cyan   = "\033[36m"
)

func rank(s rules.Severity) int {
	switch s {
	case rules.SeverityCritical:
		return 0
	case rules.SeverityHigh:
		return 1
	case rules.SeverityMedium:
		return 2
	case rules.SeverityLow:
		return 3
	default:
		return 4
	}
}

// Write prints a report of findings for target to w.
func Write(w io.Writer, target string, findings []rules.Finding, color bool) {
	c := palette(color)

	var problems, inventory []rules.Finding
	for _, f := range findings {
		if f.Severity == rules.SeverityInfo {
			inventory = append(inventory, f)
		} else {
			problems = append(problems, f)
		}
	}

	sort.SliceStable(problems, func(i, j int) bool {
		if rank(problems[i].Severity) != rank(problems[j].Severity) {
			return rank(problems[i].Severity) < rank(problems[j].Severity)
		}
		if problems[i].File != problems[j].File {
			return problems[i].File < problems[j].File
		}
		return problems[i].Line < problems[j].Line
	})

	fmt.Fprintf(w, "\n%scryptobom%s  scan of %s%s%s\n\n", c.bold, c.reset, c.cyan, target, c.reset)

	if len(problems) == 0 {
		fmt.Fprintf(w, "  %sNo cryptographic issues found.%s\n", c.dim, c.reset)
	}
	for _, f := range problems {
		sevCol := c.sevColor(f.Severity)
		scope := ""
		if f.Scope == "test" {
			scope = fmt.Sprintf(" %s[test]%s", c.dim, c.reset)
		}
		fmt.Fprintf(w, "  %s%-8s%s %s%s\n", sevCol, sevLabel(f.Severity), c.reset, f.Title, scope)
		fmt.Fprintf(w, "    %s%s:%d%s  %s%s%s\n", c.dim, f.File, f.Line, c.reset, c.dim, f.Evidence, c.reset)
		fmt.Fprintf(w, "    %srule %s · %s%s\n", c.dim, f.RuleID, f.Category, c.reset)
		if f.Remediation != "" {
			fmt.Fprintf(w, "    %s→ %s%s\n", c.dim, f.Remediation, c.reset)
		}
		fmt.Fprintln(w)
	}

	writeSummary(w, c, problems, inventory)
}

func writeSummary(w io.Writer, c colors, problems, inventory []rules.Finding) {
	counts := map[rules.Severity]int{}
	for _, f := range problems {
		counts[f.Severity]++
	}
	fmt.Fprintf(w, "%s──%s\n", c.dim, c.reset)
	fmt.Fprintf(w, "%d issue(s): ", len(problems))
	order := []rules.Severity{rules.SeverityCritical, rules.SeverityHigh, rules.SeverityMedium, rules.SeverityLow}
	first := true
	for _, s := range order {
		if counts[s] == 0 {
			continue
		}
		if !first {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprintf(w, "%s%d %s%s", c.sevColor(s), counts[s], s, c.reset)
		first = false
	}
	if first {
		fmt.Fprint(w, "none")
	}
	fmt.Fprintln(w)
	if len(inventory) > 0 {
		fmt.Fprintf(w, "%s%d other cryptographic asset(s) inventoried (see CBOM).%s\n", c.dim, len(inventory), c.reset)
	}
	fmt.Fprintln(w)
}

func sevLabel(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return "CRITICAL"
	case rules.SeverityHigh:
		return "HIGH"
	case rules.SeverityMedium:
		return "MEDIUM"
	case rules.SeverityLow:
		return "LOW"
	default:
		return "INFO"
	}
}

type colors struct {
	reset, bold, dim, cyan string
	on                     bool
}

func (c colors) sevColor(s rules.Severity) string {
	if !c.on {
		return ""
	}
	switch s {
	case rules.SeverityCritical, rules.SeverityHigh:
		return red
	case rules.SeverityMedium:
		return yellow
	case rules.SeverityLow:
		return blue
	default:
		return dim
	}
}

func palette(on bool) colors {
	if !on {
		return colors{}
	}
	return colors{reset: reset, bold: bold, dim: dim, cyan: cyan, on: true}
}
