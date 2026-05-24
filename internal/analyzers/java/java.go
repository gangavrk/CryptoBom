// Package java detects cryptographic usage in Java source via tree-sitter.
//
// It recognizes the standard JCA factory pattern, <Factory>.getInstance("alg"),
// where the algorithm is a string literal. Calls whose argument is a variable or
// expression are deliberately ignored: resolving them needs dataflow we don't
// have, and guessing would produce false positives.
package java

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/java"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses Java source and returns crypto findings located in path.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(java.GetLanguage())

	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	var findings []rules.Finding
	walk(tree.RootNode(), src, path, &findings)
	return findings, nil
}

func walk(n *sitter.Node, src []byte, path string, out *[]rules.Finding) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "method_invocation":
		if f, ok := evalCall(n, src, path); ok {
			*out = append(*out, f...)
		}
	case "object_creation_expression":
		*out = append(*out, evalNew(n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, out)
	}
}

// evalNew flags hardcoded keys (new SecretKeySpec(literal, "ALG")) and static IVs
// (new IvParameterSpec(literal)) — cases where a constructor argument is a literal.
func evalNew(node *sitter.Node, src []byte, path string) []rules.Finding {
	t := node.ChildByFieldName("type")
	args := node.ChildByFieldName("arguments")
	if t == nil || args == nil {
		return nil
	}
	var m rules.Match
	switch afterLastDot(t.Content(src)) {
	case "SecretKeySpec":
		if isLiteralBytes(args.NamedChild(0)) {
			m = rules.HardcodedKey(stringArgAt(args, 1, src))
		}
	case "IvParameterSpec":
		if isLiteralBytes(args.NamedChild(0)) {
			m = rules.StaticIV("")
		}
	}
	if m.RuleID == "" {
		return nil
	}
	pt := node.StartPoint()
	return []rules.Finding{{
		Match: m, File: path,
		Line: int(pt.Row) + 1, Column: int(pt.Column) + 1,
		Evidence: snippet(node, src),
	}}
}

// isLiteralBytes reports whether a node is literal key material: a string literal
// or a call on one (e.g. "secret".getBytes() / "secret".toCharArray()).
func isLiteralBytes(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string_literal":
		return true
	case "method_invocation":
		if obj := n.ChildByFieldName("object"); obj != nil && obj.Type() == "string_literal" {
			return true
		}
	}
	return false
}

// stringArgAt returns the unquoted value of the i-th argument if it is a string
// literal, else "".
func stringArgAt(args *sitter.Node, i int, src []byte) string {
	if args == nil || i >= int(args.NamedChildCount()) {
		return ""
	}
	if a := args.NamedChild(i); a.Type() == "string_literal" {
		return unquote(a.Content(src))
	}
	return ""
}

// evalCall inspects a method_invocation for a recognized getInstance call.
func evalCall(call *sitter.Node, src []byte, path string) ([]rules.Finding, bool) {
	name := call.ChildByFieldName("name")
	if name == nil || name.Content(src) != "getInstance" {
		return nil, false
	}
	obj := call.ChildByFieldName("object")
	if obj == nil {
		return nil, false
	}
	className := afterLastDot(obj.Content(src))
	if !rules.IsFactory(className) {
		return nil, false
	}
	args := call.ChildByFieldName("arguments")
	arg, ok := firstStringLiteral(args, src)
	if !ok {
		return nil, false
	}

	matches := rules.Evaluate(className, arg)
	if len(matches) == 0 {
		return nil, false
	}

	pt := call.StartPoint()
	findings := make([]rules.Finding, 0, len(matches))
	for _, m := range matches {
		findings = append(findings, rules.Finding{
			Match:    m,
			File:     path,
			Line:     int(pt.Row) + 1,
			Column:   int(pt.Column) + 1,
			Evidence: snippet(call, src),
		})
	}
	return findings, true
}

// firstStringLiteral returns the unquoted value of the first string-literal
// argument, or false if the first argument is not a plain string literal.
func firstStringLiteral(args *sitter.Node, src []byte) (string, bool) {
	if args == nil {
		return "", false
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		child := args.NamedChild(i)
		if child.Type() == "string_literal" {
			return unquote(child.Content(src)), true
		}
		// Stop at the first argument: only getInstance's leading string matters,
		// and a non-literal first arg means we can't analyze it safely.
		return "", false
	}
	return "", false
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "\"")
	s = strings.TrimSuffix(s, "\"")
	return s
}

func afterLastDot(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "."); i >= 0 {
		return s[i+1:]
	}
	return s
}

func snippet(n *sitter.Node, src []byte) string {
	s := n.Content(src)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
