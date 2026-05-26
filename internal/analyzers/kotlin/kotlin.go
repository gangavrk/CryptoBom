// Package kotlin detects cryptographic usage in Kotlin source via tree-sitter.
//
// Kotlin runs on the JVM and uses the same JCA APIs as Java (Cipher.getInstance,
// MessageDigest, KeyPairGenerator, SecretKeySpec, …), so detection reuses the
// shared rules. Only the syntax differs: method calls are call_expression ->
// navigation_expression + call_suffix, constructors are call_expression with a
// bare identifier callee (no `new`), and byte keys come from "literal".toByteArray().
package kotlin

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/kotlin"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses Kotlin source and returns crypto findings located in path.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(kotlin.GetLanguage())

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
	if n.Type() == "call_expression" {
		*out = append(*out, evalCall(n, src, path, df)...)
		*out = append(*out, evalTimingCompare(n, src, path, df)...)
		*out = append(*out, evalProtocolSetter(n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, df, out)
	}
}

// evalProtocolSetter flags setEnabledProtocols/setProtocols("TLSv1.1", …) calls.
func evalProtocolSetter(call *sitter.Node, src []byte, path string) []rules.Finding {
	_, method := callRecvMethod(call, src)
	if method != "setEnabledProtocols" && method != "setProtocols" {
		return nil
	}
	var matches []rules.Match
	for _, s := range collectStringLiterals(call, src) {
		matches = append(matches, rules.EvalProtocol(s)...)
	}
	if len(matches) == 0 {
		return nil
	}
	return findingsFrom(matches, call, src, path)
}

// collectStringLiterals returns the values of all string literals under n.
func collectStringLiterals(n *sitter.Node, src []byte) []string {
	var out []string
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil {
			return
		}
		if x.Type() == "string_literal" {
			if s, ok := stringOf(x, src); ok {
				out = append(out, s)
			}
			return
		}
		for i := 0; i < int(x.NamedChildCount()); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(n)
	return out
}

// evalTimingCompare flags Arrays.equals(...) / x.equals(...) / x.contentEquals(...)
// where an operand is a MAC/digest. MessageDigest.isEqual is the safe form and is
// named differently, so it is never matched.
func evalTimingCompare(call *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	recv, method := callRecvMethod(call, src)
	if method != "equals" && method != "contentEquals" {
		return nil
	}
	args := argExprs(call)
	scope := enclosingScope(call)

	var flagged bool
	if recv != nil && recv.Type() == "simple_identifier" && recv.Content(src) == "Arrays" {
		flagged = anyMacArg(args, src, df, scope) // Arrays.equals(a, b)
	} else {
		flagged = isMacExpr(recv, src, df, scope) || anyMacArg(args, src, df, scope)
	}
	if !flagged {
		return nil
	}
	return findingsFrom([]rules.Match{rules.TimingCompare()}, call, src, path)
}

// isMacExpr reports whether a node is a MAC/digest value: a tagged variable or a
// direct macObj.doFinal()/.digest() call.
func isMacExpr(n *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if n == nil {
		return false
	}
	if n.Type() == "simple_identifier" {
		return df.macTag[varKey(scope, n.Content(src))]
	}
	if n.Type() == "call_expression" {
		recv, method := callRecvMethod(n, src)
		if recv != nil && recv.Type() == "simple_identifier" && (method == "doFinal" || method == "digest") {
			return df.macObj[varKey(scope, recv.Content(src))]
		}
	}
	return false
}

func anyMacArg(args []*sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	for _, a := range args {
		if isMacExpr(a, src, df, scope) {
			return true
		}
	}
	return false
}

func evalCall(call *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	callee := firstNamedChild(call)
	if callee == nil {
		return nil
	}
	switch callee.Type() {
	case "navigation_expression": // receiver.method(...)
		return evalMethodCall(call, callee, src, path, df)
	case "simple_identifier": // Ctor(...) / function(...)
		return evalCtorCall(call, callee.Content(src), src, path, df)
	}
	return nil
}

// evalMethodCall handles <Factory>.getInstance("ALG").
func evalMethodCall(call, callee *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	if navMethod(callee, src) != "getInstance" {
		return nil
	}
	className := receiverName(navReceiver(callee), src)
	if !rules.IsFactory(className) {
		return nil
	}
	arg, ok := firstArgString(call, src)
	if !ok {
		return nil
	}
	matches := rules.Evaluate(className, arg)
	if len(matches) == 0 {
		return nil
	}
	// Link a KeyPairGenerator's key size from a later var.initialize(bits) call.
	if className == "KeyPairGenerator" {
		if v := assignedVar(call, src); v != "" {
			if bits := df.keySize[varKey(enclosingScope(call), v)]; bits > 0 {
				matches = rules.AnnotateKey(matches, bits, "")
			}
		}
	}
	return findingsFrom(matches, call, src, path)
}

// evalCtorCall handles SecretKeySpec(...) and IvParameterSpec(...) constructors.
func evalCtorCall(call *sitter.Node, name string, src []byte, path string, df *dataflow) []rules.Finding {
	args := argExprs(call)
	var arg0 *sitter.Node
	if len(args) > 0 {
		arg0 = args[0]
	}

	var m rules.Match
	switch name {
	case "SecureRandom":
		// `SecureRandom(...)` — inventory the CSPRNG (a positive asset).
		m = rules.SecureRandomAsset("")
	case "SecretKeySpec":
		algo := ""
		if len(args) > 1 {
			if s, ok := stringOf(args[1], src); ok {
				algo = s
			}
		}
		switch {
		case isLiteralBytes(arg0):
			m = rules.HardcodedKey(algo)
		case isWeakRandomVar(arg0, src, df, call):
			m = rules.WeakPRNG(algo)
		}
	case "IvParameterSpec":
		switch {
		case isLiteralBytes(arg0):
			m = rules.StaticIV("")
		case isWeakRandomVar(arg0, src, df, call):
			m = rules.WeakPRNG("")
		}
	}
	if m.RuleID == "" {
		return nil
	}
	return findingsFrom([]rules.Match{m}, call, src, path)
}

func findingsFrom(matches []rules.Match, call *sitter.Node, src []byte, path string) []rules.Finding {
	pt := call.StartPoint()
	out := make([]rules.Finding, 0, len(matches))
	for _, m := range matches {
		out = append(out, rules.Finding{
			Match:    m,
			File:     path,
			Line:     int(pt.Row) + 1,
			Column:   int(pt.Column) + 1,
			Evidence: snippet(call, src),
		})
	}
	return out
}

// isWeakRandomVar reports whether arg is an identifier the dataflow pass marked as
// holding output from a non-cryptographic PRNG.
func isWeakRandomVar(arg *sitter.Node, src []byte, df *dataflow, call *sitter.Node) bool {
	return arg != nil && arg.Type() == "simple_identifier" &&
		df.weakRandom[varKey(enclosingScope(call), arg.Content(src))]
}

// --- AST navigation helpers ---

func firstNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

func lastNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(int(n.NamedChildCount()) - 1)
}

func childOfType(n *sitter.Node, t string) *sitter.Node {
	if n == nil {
		return nil
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if c := n.NamedChild(i); c.Type() == t {
			return c
		}
	}
	return nil
}

func navReceiver(nav *sitter.Node) *sitter.Node { return firstNamedChild(nav) }

func navMethod(nav *sitter.Node, src []byte) string {
	if s := childOfType(nav, "navigation_suffix"); s != nil {
		if id := childOfType(s, "simple_identifier"); id != nil {
			return id.Content(src)
		}
	}
	return ""
}

// receiverName is the trailing identifier of a call receiver (e.g. "Cipher" from
// `Cipher` or `javax.crypto.Cipher`).
func receiverName(recv *sitter.Node, src []byte) string {
	if recv == nil {
		return ""
	}
	switch recv.Type() {
	case "simple_identifier":
		return recv.Content(src)
	case "navigation_expression":
		return navMethod(recv, src)
	}
	return ""
}

// argExprs returns the expression node of each value_argument in a call.
func argExprs(call *sitter.Node) []*sitter.Node {
	cs := childOfType(call, "call_suffix")
	if cs == nil {
		return nil
	}
	va := childOfType(cs, "value_arguments")
	if va == nil {
		return nil
	}
	var out []*sitter.Node
	for i := 0; i < int(va.NamedChildCount()); i++ {
		if arg := va.NamedChild(i); arg.Type() == "value_argument" {
			out = append(out, lastNamedChild(arg))
		}
	}
	return out
}

func firstArgString(call *sitter.Node, src []byte) (string, bool) {
	args := argExprs(call)
	if len(args) == 0 {
		return "", false
	}
	return stringOf(args[0], src)
}

// stringOf returns a string literal's value (false if n is not a string literal).
func stringOf(n *sitter.Node, src []byte) (string, bool) {
	if n == nil || n.Type() != "string_literal" {
		return "", false
	}
	if sc := childOfType(n, "string_content"); sc != nil {
		return sc.Content(src), true
	}
	return "", true // empty string literal
}

// isLiteralBytes reports whether a node is literal key material: a string literal
// or "literal".toByteArray() / "literal".toCharArray().
func isLiteralBytes(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	if n.Type() == "string_literal" {
		return true
	}
	if n.Type() == "call_expression" {
		if callee := firstNamedChild(n); callee != nil && callee.Type() == "navigation_expression" {
			if r := navReceiver(callee); r != nil && r.Type() == "string_literal" {
				return true
			}
		}
	}
	return false
}

// assignedVar returns the variable a call's result is bound to in `val x = call`.
func assignedVar(call *sitter.Node, src []byte) string {
	if p := call.Parent(); p != nil && p.Type() == "property_declaration" {
		return propertyName(p, src)
	}
	return ""
}

func snippet(n *sitter.Node, src []byte) string {
	s := n.Content(src)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func varKey(scope uint32, name string) string {
	return fmt.Sprintf("%d:%s", scope, name)
}
