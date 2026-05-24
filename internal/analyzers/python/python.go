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

	var findings []rules.Finding
	walk(tree.RootNode(), src, path, &findings)
	return findings, nil
}

func walk(n *sitter.Node, src []byte, path string, out *[]rules.Finding) {
	if n == nil {
		return
	}
	if n.Type() == "call" {
		*out = append(*out, evalCall(n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, out)
	}
}

func evalCall(call *sitter.Node, src []byte, path string) []rules.Finding {
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
	if len(matches) == 0 {
		return nil
	}
	if bits, curve := keyParams(obj, attr, args, src); bits > 0 || curve != "" {
		matches = rules.AnnotateKey(matches, bits, curve)
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
