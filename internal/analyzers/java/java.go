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

	root := tree.RootNode()
	df := buildDataflow(root, src)

	var findings []rules.Finding
	walk(root, src, path, df, &findings)
	return findings, nil
}

func walk(n *sitter.Node, src []byte, path string, df *dataflow, out *[]rules.Finding) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "method_invocation":
		if f, ok := evalCall(n, src, path, df); ok {
			*out = append(*out, f...)
		}
		*out = append(*out, evalTimingCompare(n, src, path, df)...)
		*out = append(*out, evalProtocolSetter(n, src, path)...)
	case "object_creation_expression":
		*out = append(*out, evalNew(n, src, path, df)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, df, out)
	}
}

// evalNew flags key/IV constructor misuse: a hardcoded literal, or (via dataflow)
// a value drawn from a non-cryptographic PRNG — for SecretKeySpec and IvParameterSpec.
func evalNew(node *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	t := node.ChildByFieldName("type")
	args := node.ChildByFieldName("arguments")
	if t == nil || args == nil {
		return nil
	}
	arg0 := args.NamedChild(0)

	var m rules.Match
	switch afterLastDot(t.Content(src)) {
	case "SecretKeySpec":
		algo := stringArgAt(args, 1, src)
		switch {
		case isLiteralBytes(arg0):
			m = rules.HardcodedKey(algo)
		case isWeakRandomVar(arg0, src, df, node):
			m = rules.WeakPRNG(algo)
		}
	case "IvParameterSpec":
		switch {
		case isLiteralBytes(arg0):
			m = rules.StaticIV("")
		case isWeakRandomVar(arg0, src, df, node):
			m = rules.WeakPRNG("")
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

// isWeakRandomVar reports whether arg is an identifier the dataflow pass marked as
// holding output from a non-cryptographic PRNG.
func isWeakRandomVar(arg *sitter.Node, src []byte, df *dataflow, node *sitter.Node) bool {
	return arg != nil && arg.Type() == "identifier" &&
		df.weakRandom[varKey(enclosingScope(node), arg.Content(src))]
}

// evalProtocolSetter flags setEnabledProtocols/setProtocols(... "TLSv1.1" ...) calls.
// Only string literals that resolve to a known protocol are reported, so unrelated
// setProtocols calls produce nothing.
func evalProtocolSetter(call *sitter.Node, src []byte, path string) []rules.Finding {
	switch callName(call, src) {
	case "setEnabledProtocols", "setProtocols":
	default:
		return nil
	}
	pt := call.StartPoint()
	var out []rules.Finding
	for _, s := range collectStringLiterals(call.ChildByFieldName("arguments"), src) {
		for _, m := range rules.EvalProtocol(s) {
			out = append(out, rules.Finding{
				Match: m, File: path,
				Line: int(pt.Row) + 1, Column: int(pt.Column) + 1, Evidence: snippet(call, src),
			})
		}
	}
	return out
}

// collectStringLiterals returns the unquoted values of all string literals under n.
func collectStringLiterals(n *sitter.Node, src []byte) []string {
	var out []string
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil {
			return
		}
		if x.Type() == "string_literal" {
			out = append(out, unquote(x.Content(src)))
			return
		}
		for i := 0; i < int(x.NamedChildCount()); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(n)
	return out
}

// evalTimingCompare flags Arrays.equals(...) / x.equals(...) where an operand is a
// MAC/digest (a variable-time comparison). MessageDigest.isEqual is the safe form
// and is named differently, so it is never matched.
func evalTimingCompare(call *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	if callName(call, src) != "equals" {
		return nil
	}
	obj := call.ChildByFieldName("object")
	args := call.ChildByFieldName("arguments")
	scope := enclosingScope(call)

	var flagged bool
	if obj != nil && obj.Type() == "identifier" && obj.Content(src) == "Arrays" {
		flagged = anyArgMac(args, src, df, scope) // Arrays.equals(a, b)
	} else {
		flagged = isMacExpr(obj, src, df, scope) || anyArgMac(args, src, df, scope) // x.equals(y)
	}
	if !flagged {
		return nil
	}
	pt := call.StartPoint()
	return []rules.Finding{{
		Match: rules.TimingCompare(), File: path,
		Line: int(pt.Row) + 1, Column: int(pt.Column) + 1,
		Evidence: snippet(call, src),
	}}
}

// isMacExpr reports whether a node is a MAC/digest value: a tagged variable, or a
// direct macObj.doFinal()/.digest() call.
func isMacExpr(n *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if n == nil {
		return false
	}
	if n.Type() == "identifier" {
		return df.macTag[varKey(scope, n.Content(src))]
	}
	if n.Type() == "method_invocation" {
		o := n.ChildByFieldName("object")
		nm := callName(n, src)
		if o != nil && o.Type() == "identifier" && (nm == "doFinal" || nm == "digest") {
			return df.macObj[varKey(scope, o.Content(src))]
		}
	}
	return false
}

func anyArgMac(args *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if args == nil {
		return false
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if isMacExpr(args.NamedChild(i), src, df, scope) {
			return true
		}
	}
	return false
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

// assignedVar returns the name of the variable a call's result is assigned to,
// looking at the immediate declaration or assignment, or "" if not assigned.
func assignedVar(call *sitter.Node, src []byte) string {
	p := call.Parent()
	if p == nil {
		return ""
	}
	switch p.Type() {
	case "variable_declarator":
		if n := p.ChildByFieldName("name"); n != nil {
			return n.Content(src)
		}
	case "assignment_expression":
		if l := p.ChildByFieldName("left"); l != nil && l.Type() == "identifier" {
			return l.Content(src)
		}
	}
	return ""
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
func evalCall(call *sitter.Node, src []byte, path string, df *dataflow) ([]rules.Finding, bool) {
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

	// Link a KeyPairGenerator's key size from a later var.initialize(bits) call.
	if className == "KeyPairGenerator" {
		if v := assignedVar(call, src); v != "" {
			if bits := df.keySize[varKey(enclosingScope(call), v)]; bits > 0 {
				matches = rules.AnnotateKey(matches, bits, "")
			}
		}
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
