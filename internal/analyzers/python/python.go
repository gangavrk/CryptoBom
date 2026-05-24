// Package python detects cryptographic usage in Python source via tree-sitter.
//
// It recognizes qualified calls from the two dominant libraries — pyca/cryptography
// and pycryptodome — such as hashlib.md5(), modes.ECB(), AES.new(key, AES.MODE_ECB),
// and rsa.generate_private_key(...). Bare, unqualified names are left alone:
// resolving them needs import/alias tracking we don't yet do, and guessing would
// produce false positives.
package python

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses Python source and returns crypto findings located in path.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(python.GetLanguage())

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
	case "call":
		*out = append(*out, evalCall(n, src, path, df)...)
	case "comparison_operator":
		*out = append(*out, evalComparison(n, src, path, df)...)
	case "attribute":
		*out = append(*out, evalProtocolAttr(n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, df, out)
	}
}

// evalComparison flags `a == b` / `a != b` where an operand is a MAC/digest.
func evalComparison(node *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	if node.NamedChildCount() != 2 { // skip chained comparisons (a < b < c)
		return nil
	}
	op := node.ChildByFieldName("operators")
	if op == nil || (op.Type() != "==" && op.Type() != "!=") {
		return nil
	}
	left, right := node.NamedChild(0), node.NamedChild(1)
	scope := enclosingScope(node)
	if !isMacOperand(left, src, df, scope) && !isMacOperand(right, src, df, scope) {
		return nil
	}
	pt := node.StartPoint()
	return []rules.Finding{{
		Match:    rules.TimingCompare(),
		File:     path,
		Line:     int(pt.Row) + 1,
		Column:   int(pt.Column) + 1,
		Evidence: snippet(node, src),
	}}
}

// evalProtocolAttr flags ssl.PROTOCOL_TLSv1 / ssl.TLSVersion.TLSv1 protocol constants.
func evalProtocolAttr(node *sitter.Node, src []byte, path string) []rules.Finding {
	obj := node.ChildByFieldName("object")
	attr := node.ChildByFieldName("attribute")
	if attr == nil || obj == nil {
		return nil
	}
	name := attr.Content(src)
	var tok string
	switch {
	case obj.Type() == "identifier" && obj.Content(src) == "ssl" && strings.HasPrefix(name, "PROTOCOL_"):
		tok = pyTLSToken(name) // ssl.PROTOCOL_TLSv1
	case obj.Type() == "attribute" && simpleName(obj, src) == "TLSVersion":
		tok = pyTLSToken(name) // ssl.TLSVersion.TLSv1
	}
	if tok == "" {
		return nil
	}
	pt := node.StartPoint()
	out := make([]rules.Finding, 0, 1)
	for _, m := range rules.EvalProtocol(tok) {
		out = append(out, rules.Finding{
			Match: m, File: path,
			Line: int(pt.Row) + 1, Column: int(pt.Column) + 1, Evidence: snippet(node, src),
		})
	}
	return out
}

func pyTLSToken(name string) string {
	switch strings.TrimPrefix(name, "PROTOCOL_") {
	case "SSLv2":
		return "SSLv2"
	case "SSLv3":
		return "SSLv3"
	case "TLSv1":
		return "TLSv1.0"
	case "TLSv1_1":
		return "TLSv1.1"
	case "TLSv1_2":
		return "TLSv1.2"
	case "TLSv1_3":
		return "TLSv1.3"
	case "TLS", "TLS_CLIENT", "TLS_SERVER":
		return "TLS"
	}
	return ""
}

func isMacOperand(n *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if n == nil {
		return false
	}
	if n.Type() == "identifier" {
		return df.macTag[varKey(scope, n.Content(src))]
	}
	return isMacSourceCall(n, src)
}

// isMacSourceCall reports whether a call is `<hmac|hashlib>....digest()`/`.hexdigest()`.
func isMacSourceCall(call *sitter.Node, src []byte) bool {
	if call == nil || call.Type() != "call" {
		return false
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return false
	}
	if attr := fn.ChildByFieldName("attribute"); attr == nil ||
		(attr.Content(src) != "digest" && attr.Content(src) != "hexdigest") {
		return false
	}
	inner := fn.ChildByFieldName("object")
	if inner == nil || inner.Type() != "call" {
		return false
	}
	innerFn := inner.ChildByFieldName("function")
	if innerFn == nil || innerFn.Type() != "attribute" {
		return false
	}
	obj := simpleName(innerFn.ChildByFieldName("object"), src)
	return obj == "hmac" || obj == "hashlib"
}

func evalCall(call *sitter.Node, src []byte, path string, df *dataflow) []rules.Finding {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "attribute" {
		return nil // only qualified calls (obj.method)
	}
	obj := simpleName(fn.ChildByFieldName("object"), src)
	attrNode := fn.ChildByFieldName("attribute")
	if obj == "" || attrNode == nil {
		return nil
	}
	attr := attrNode.Content(src)

	args := call.ChildByFieldName("arguments")
	matches := rules.PyEvaluate(obj, attr, firstString(args, src), hasModeECB(args, src))
	if bits, curve := keyParams(obj, attr, args, src); bits > 0 || curve != "" {
		matches = rules.AnnotateKey(matches, bits, curve)
	}
	matches = append(matches, pyMisuse(obj, attr, args, src, df, enclosingScope(call))...)
	if len(matches) == 0 {
		return nil
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
	return findings
}

// simpleName returns the trailing name of an identifier or attribute node
// (e.g. "hashlib" from `hashlib`, "MD5" from `Crypto.Hash.MD5`).
func simpleName(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		return n.Content(src)
	case "attribute":
		if a := n.ChildByFieldName("attribute"); a != nil {
			return a.Content(src)
		}
	}
	return ""
}

// firstString returns the value of the first top-level string argument, if any.
func firstString(args *sitter.Node, src []byte) string {
	if args == nil {
		return ""
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		child := args.NamedChild(i)
		if child.Type() == "string" {
			for j := 0; j < int(child.NamedChildCount()); j++ {
				if part := child.NamedChild(j); part.Type() == "string_content" {
					return part.Content(src)
				}
			}
			return "" // empty string literal
		}
	}
	return ""
}

// hasModeECB reports whether MODE_ECB appears anywhere in the argument list.
func hasModeECB(args *sitter.Node, src []byte) bool {
	if args == nil {
		return false
	}
	found := false
	var scan func(n *sitter.Node)
	scan = func(n *sitter.Node) {
		if n == nil || found {
			return
		}
		if n.Type() == "identifier" && n.Content(src) == "MODE_ECB" {
			found = true
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			scan(n.NamedChild(i))
		}
	}
	scan(args)
	return found
}

var pyCipherCtor = map[string]bool{
	"AES": true, "DES": true, "DES3": true, "ARC4": true, "ARC2": true,
	"Blowfish": true, "ChaCha20": true,
}

var pyCipherClass = map[string]bool{
	"AES": true, "Camellia": true, "TripleDES": true, "ARC4": true,
	"Blowfish": true, "IDEA": true, "SEED": true, "SM4": true, "ChaCha20": true,
}

var pyStaticIVMode = map[string]bool{"CBC": true, "CTR": true, "OFB": true, "CFB": true}

// pyMisuse flags hardcoded keys / static IVs (a literal where a key/IV is expected)
// and weak-PRNG key/IV material (a value from the random module reaching that slot).
func pyMisuse(obj, attr string, args *sitter.Node, src []byte, df *dataflow, scope uint32) []rules.Match {
	var out []rules.Match
	weakArg0 := func() bool { return df.weakRandom[varKey(scope, firstArgIdent(args, src))] }

	switch {
	case attr == "new" && pyCipherCtor[obj]: // pycryptodome: AES.new(b"...", mode, iv=b"...")
		switch {
		case firstArgIsString(args):
			out = append(out, rules.HardcodedKey(pyCipherName(obj)))
		case weakArg0():
			out = append(out, rules.WeakPRNG(pyCipherName(obj)))
		}
		switch {
		case keywordIsString(args, "iv", src) || keywordIsString(args, "nonce", src):
			out = append(out, rules.StaticIV(pyCipherName(obj)))
		case df.weakRandom[varKey(scope, keywordIdent(args, "iv", src))]:
			out = append(out, rules.WeakPRNG(pyCipherName(obj)))
		}
	case obj == "algorithms" && pyCipherClass[attr]: // cryptography: algorithms.AES(b"...")
		switch {
		case firstArgIsString(args):
			out = append(out, rules.HardcodedKey(attr))
		case weakArg0():
			out = append(out, rules.WeakPRNG(attr))
		}
	case obj == "modes" && pyStaticIVMode[attr]: // cryptography: modes.CBC(b"...")
		switch {
		case firstArgIsString(args):
			out = append(out, rules.StaticIV(""))
		case weakArg0():
			out = append(out, rules.WeakPRNG(""))
		}
	}
	return out
}

func firstArgIdent(args *sitter.Node, src []byte) string {
	if args != nil && args.NamedChildCount() > 0 {
		if c := args.NamedChild(0); c.Type() == "identifier" {
			return c.Content(src)
		}
	}
	return ""
}

func keywordIdent(args *sitter.Node, name string, src []byte) string {
	if v := keywordValue(args, name, src); v != nil && v.Type() == "identifier" {
		return v.Content(src)
	}
	return ""
}

func pyCipherName(obj string) string {
	switch obj {
	case "DES3":
		return "3DES"
	case "ARC4":
		return "RC4"
	case "ARC2":
		return "RC2"
	}
	return obj
}

func firstArgIsString(args *sitter.Node) bool {
	return args != nil && args.NamedChildCount() > 0 && args.NamedChild(0).Type() == "string"
}

func keywordIsString(args *sitter.Node, name string, src []byte) bool {
	v := keywordValue(args, name, src)
	return v != nil && v.Type() == "string"
}

// keyParams extracts an asymmetric key size or curve from a keygen call,
// aware of each library's argument convention.
func keyParams(obj, attr string, args *sitter.Node, src []byte) (bits int, curve string) {
	switch {
	case attr == "generate_private_key" && (obj == "rsa" || obj == "dsa"):
		return keywordInt(args, "key_size", src), ""
	case attr == "generate" && (obj == "RSA" || obj == "DSA"):
		if b := keywordInt(args, "bits", src); b > 0 {
			return b, ""
		}
		return firstPositionalInt(args, src), ""
	case attr == "generate_private_key" && obj == "ec":
		return 0, firstPositionalName(args, src)
	case attr == "generate" && obj == "ECC":
		return 0, keywordString(args, "curve", src)
	}
	return 0, ""
}

func atoi(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// keywordInt returns the integer value of keyword argument name, or 0.
func keywordInt(args *sitter.Node, name string, src []byte) int {
	if v := keywordValue(args, name, src); v != nil && v.Type() == "integer" {
		return atoi(v.Content(src))
	}
	return 0
}

// keywordString returns the unquoted value of a string keyword argument, or "".
func keywordString(args *sitter.Node, name string, src []byte) string {
	if v := keywordValue(args, name, src); v != nil && v.Type() == "string" {
		for j := 0; j < int(v.NamedChildCount()); j++ {
			if part := v.NamedChild(j); part.Type() == "string_content" {
				return part.Content(src)
			}
		}
	}
	return ""
}

func keywordValue(args *sitter.Node, name string, src []byte) *sitter.Node {
	if args == nil {
		return nil
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		kw := args.NamedChild(i)
		if kw.Type() != "keyword_argument" {
			continue
		}
		if n := kw.ChildByFieldName("name"); n != nil && n.Content(src) == name {
			return kw.ChildByFieldName("value")
		}
	}
	return nil
}

// firstPositionalInt returns the first positional integer argument, or 0.
func firstPositionalInt(args *sitter.Node, src []byte) int {
	if args == nil {
		return 0
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if c := args.NamedChild(i); c.Type() == "integer" {
			return atoi(c.Content(src))
		}
	}
	return 0
}

// firstPositionalName returns the trailing name of the first positional argument,
// handling forms like ec.SECP256R1() (call), ec.SECP256R1 (attribute), or NAME.
func firstPositionalName(args *sitter.Node, src []byte) string {
	if args == nil {
		return ""
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		c := args.NamedChild(i)
		switch c.Type() {
		case "keyword_argument":
			continue
		case "call":
			return simpleName(c.ChildByFieldName("function"), src)
		case "attribute", "identifier":
			return simpleName(c, src)
		}
		return ""
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
