// Package golang detects cryptographic usage in Go source using the standard
// library's own parser (go/ast). Detection is precise: a call only matches if its
// selector resolves through the file's imports to a known crypto package, so a
// method on an unrelated variable is never mistaken for a crypto call.
package golang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses Go source and returns crypto findings located in filename.
func Analyze(filename string, src []byte) ([]rules.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if file == nil {
		return nil, err // unrecoverable parse failure
	}

	imports := importMap(file)

	var findings []rules.Finding
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath, ok := imports[pkgIdent.Name]
		if !ok {
			return true
		}

		for _, m := range rules.GoEvaluate(pkgPath, sel.Sel.Name) {
			pos := fset.Position(call.Pos())
			findings = append(findings, rules.Finding{
				Match:    m,
				File:     filename,
				Line:     pos.Line,
				Column:   pos.Column,
				Evidence: snippet(src, fset, call),
			})
		}
		return true
	})
	return findings, nil
}

// importMap maps each import's local name to its package path, skipping blank
// and dot imports (calls through those can't be attributed to a package name).
func importMap(file *ast.File) map[string]string {
	m := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		m[name] = path
	}
	return m
}

func snippet(src []byte, fset *token.FileSet, call *ast.CallExpr) string {
	start := fset.Position(call.Pos()).Offset
	end := fset.Position(call.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	s := string(src[start:end])
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
