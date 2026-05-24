// Package csharp detects cryptographic usage in C# / .NET source via tree-sitter.
//
// .NET puts the algorithm in the type name (MD5.Create(), new RSACryptoServiceProvider(),
// Aes.Create()) rather than a string argument, so detection is type-based and maps to
// the shared rules. ECB is the CipherMode.ECB enum, and keys/IVs are set via the .Key
// and .IV properties.
package csharp

import (
	"context"
	"fmt"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/csharp"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses C# source and returns crypto findings located in path.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(csharp.GetLanguage())

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
	case "invocation_expression":
		*out = append(*out, evalInvocation(n, src, path)...)
	case "object_creation_expression":
		*out = append(*out, evalNew(n, src, path)...)
	case "member_access_expression":
		*out = append(*out, evalMemberAccess(n, src, path)...)
	case "assignment_expression":
		*out = append(*out, evalAssign(n, src, path, df)...)
	}
	switch n.Type() {
	case "invocation_expression":
		*out = append(*out, evalTimingInvocation(n, src, path, df)...)
	case "binary_expression":
		*out = append(*out, evalTimingBinary(n, src, path, df)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, df, out)
	}
}

// evalInvocation handles static factory/one-shot calls like RSA.Create(2048) or
// MD5.HashData(data), where the receiver is a crypto type name.
func evalInvocation(call *sitter.Node, src []byte, path string) []rules.Finding {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_access_expression" {
		return nil
	}
	recv := fn.ChildByFieldName("expression")
	if recv == nil || recv.Type() != "identifier" {
		return nil
	}
	matches := rules.CSharpEvaluate(recv.Content(src))
	if len(matches) == 0 {
		return nil
	}
	if bits := firstIntArg(call, src); bits > 0 {
		matches = rules.AnnotateKey(matches, bits, "")
	}
	return findingsFrom(matches, call, src, path)
}

// evalNew handles `new <CryptoType>(...)` constructions.
func evalNew(node *sitter.Node, src []byte, path string) []rules.Finding {
	t := node.ChildByFieldName("type")
	if t == nil {
		return nil
	}
	matches := rules.CSharpEvaluate(afterLastDot(t.Content(src)))
	if len(matches) == 0 {
		return nil
	}
	if bits := firstIntArg(node, src); bits > 0 {
		matches = rules.AnnotateKey(matches, bits, "")
	}
	return findingsFrom(matches, node, src, path)
}

var csTLSConst = map[string]string{
	"Ssl2": "SSLv2", "Ssl3": "SSLv3", "Tls": "TLSv1.0",
	"Tls11": "TLSv1.1", "Tls12": "TLSv1.2", "Tls13": "TLSv1.3",
}

// evalMemberAccess flags CipherMode.ECB and SslProtocols.Tls11 / .Ssl3 / ... .
func evalMemberAccess(node *sitter.Node, src []byte, path string) []rules.Finding {
	expr := node.ChildByFieldName("expression")
	name := node.ChildByFieldName("name")
	if expr == nil || name == nil || expr.Type() != "identifier" {
		return nil
	}
	switch expr.Content(src) {
	case "CipherMode":
		if name.Content(src) == "ECB" {
			return findingsFrom(rules.CSharpCipherMode("ECB"), node, src, path)
		}
	case "SslProtocols":
		if tok := csTLSConst[name.Content(src)]; tok != "" {
			return findingsFrom(rules.EvalProtocol(tok), node, src, path)
		}
	}
	return nil
}

// evalAssign flags `obj.Key = <literal>` / `obj.IV = <literal>` (hardcoded) and the
// same target assigned a value drawn from a non-cryptographic PRNG (weak-PRNG).
func evalAssign(node *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	left := node.ChildByFieldName("left")
	right := node.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != "member_access_expression" {
		return nil
	}
	prop := ""
	if nm := left.ChildByFieldName("name"); nm != nil {
		prop = nm.Content(src)
	}
	if prop != "Key" && prop != "IV" {
		return nil
	}

	var m rules.Match
	switch {
	case isLiteralBytes(right, src):
		if prop == "Key" {
			m = rules.HardcodedKey("")
		} else {
			m = rules.StaticIV("")
		}
	case isWeakRandomVar(right, src, df, node):
		m = rules.WeakPRNG("")
	}
	if m.RuleID == "" {
		return nil
	}
	return findingsFrom([]rules.Match{m}, node, src, path)
}

func isWeakRandomVar(arg *sitter.Node, src []byte, df *dataflow, node *sitter.Node) bool {
	return arg != nil && arg.Type() == "identifier" &&
		df.weakRandom[varKey(enclosingScope(node), arg.Content(src))]
}

var bytesMethods = map[string]bool{"GetBytes": true, "FromBase64String": true, "FromHexString": true}

// isLiteralBytes reports whether n is literal key material: a string literal, or a
// call like Encoding.UTF8.GetBytes("…") / Convert.FromBase64String("…").
func isLiteralBytes(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "string_literal":
		return true
	case "invocation_expression":
		fn := n.ChildByFieldName("function")
		if fn != nil && fn.Type() == "member_access_expression" {
			if nm := fn.ChildByFieldName("name"); nm != nil && bytesMethods[nm.Content(src)] {
				return hasStringArg(n, src)
			}
		}
	}
	return false
}

// evalTimingInvocation flags a.SequenceEqual(b) / Enumerable.SequenceEqual(a, b)
// where an operand is a MAC/digest. CryptographicOperations.FixedTimeEquals is the
// safe form and is named differently, so it is never matched.
func evalTimingInvocation(inv *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	recv, method := invRecvMethod(inv, src)
	if method != "SequenceEqual" {
		return nil
	}
	scope := enclosingScope(inv)
	operands := append([]*sitter.Node{recv}, argExprs(inv)...)
	for _, o := range operands {
		if isMacExpr(o, src, df, scope) {
			return findingsFrom([]rules.Match{rules.TimingCompare()}, inv, src, path)
		}
	}
	return nil
}

// evalTimingBinary flags `a == b` / `a != b` where an operand is a MAC/digest.
func evalTimingBinary(be *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	op := be.ChildByFieldName("operator")
	if op == nil || (op.Type() != "==" && op.Type() != "!=") {
		return nil
	}
	scope := enclosingScope(be)
	if isMacExpr(be.ChildByFieldName("left"), src, df, scope) ||
		isMacExpr(be.ChildByFieldName("right"), src, df, scope) {
		return findingsFrom([]rules.Match{rules.TimingCompare()}, be, src, path)
	}
	return nil
}

// isMacExpr reports whether a node is a MAC/digest value: a tagged variable, or a
// direct macObj.ComputeHash(...) / <HashType>.HashData(...) call.
func isMacExpr(n *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if n == nil {
		return false
	}
	if n.Type() == "identifier" {
		return df.macTag[varKey(scope, n.Content(src))]
	}
	if n.Type() == "invocation_expression" {
		recv, method := invRecvMethod(n, src)
		if recv != nil && recv.Type() == "identifier" {
			switch method {
			case "ComputeHash", "TransformFinalBlock":
				return df.macObj[varKey(scope, recv.Content(src))]
			case "HashData":
				return isHashOrHmac(recv.Content(src))
			}
		}
	}
	return false
}

// invRecvMethod returns the receiver expression and method name of an invocation.
func invRecvMethod(inv *sitter.Node, src []byte) (*sitter.Node, string) {
	fn := inv.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_access_expression" {
		return nil, ""
	}
	name := ""
	if nm := fn.ChildByFieldName("name"); nm != nil {
		name = nm.Content(src)
	}
	return fn.ChildByFieldName("expression"), name
}

// isHashOrHmac reports whether a .NET type name is an HMAC or hash algorithm.
func isHashOrHmac(t string) bool {
	for _, suffix := range []string{"CryptoServiceProvider", "Managed", "Cng"} {
		t = strings.TrimSuffix(t, suffix)
	}
	if strings.HasPrefix(t, "HMAC") {
		return true
	}
	switch t {
	case "MD5", "SHA1", "SHA256", "SHA384", "SHA512", "HashAlgorithm", "KeyedHashAlgorithm", "HMAC":
		return true
	}
	return false
}

func findingsFrom(matches []rules.Match, node *sitter.Node, src []byte, path string) []rules.Finding {
	pt := node.StartPoint()
	out := make([]rules.Finding, 0, len(matches))
	for _, m := range matches {
		out = append(out, rules.Finding{
			Match:    m,
			File:     path,
			Line:     int(pt.Row) + 1,
			Column:   int(pt.Column) + 1,
			Evidence: snippet(node, src),
		})
	}
	return out
}

// --- helpers ---

func argExprs(call *sitter.Node) []*sitter.Node {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	var out []*sitter.Node
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if a := args.NamedChild(i); a.Type() == "argument" {
			out = append(out, a.NamedChild(0))
		}
	}
	return out
}

func firstIntArg(call *sitter.Node, src []byte) int {
	for _, a := range argExprs(call) {
		if a != nil && a.Type() == "integer_literal" {
			return atoi(a.Content(src))
		}
		return 0 // only consider the first positional argument
	}
	return 0
}

func hasStringArg(call *sitter.Node, src []byte) bool {
	for _, a := range argExprs(call) {
		if a != nil && a.Type() == "string_literal" {
			return true
		}
	}
	return false
}

func atoi(s string) int {
	v := 0
	for _, r := range s {
		if r == '_' {
			continue
		}
		if r < '0' || r > '9' {
			return 0
		}
		v = v*10 + int(r-'0')
	}
	return v
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

func varKey(scope uint32, name string) string {
	return fmt.Sprintf("%d:%s", scope, name)
}
