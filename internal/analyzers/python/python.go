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

func snippet(n *sitter.Node, src []byte) string {
	s := n.Content(src)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
