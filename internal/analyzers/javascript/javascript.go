// Package javascript detects cryptographic usage in JavaScript and TypeScript via
// tree-sitter. It recognizes the Node.js crypto module (crypto.createHash, …),
// crypto-js (CryptoJS.MD5, CryptoJS.mode.ECB, …) and reuses the shared rules.
package javascript

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/javascript"
	"github.com/smacker/go-tree-sitter/typescript/tsx"
	"github.com/smacker/go-tree-sitter/typescript/typescript"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses JS/TS source and returns crypto findings located in path.
func Analyze(path string, src []byte) ([]rules.Finding, error) {
	parser := sitter.NewParser()
	defer parser.Close()
	parser.SetLanguage(language(path))

	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	var findings []rules.Finding
	walk(tree.RootNode(), src, path, &findings)
	return findings, nil
}

func language(path string) *sitter.Language {
	switch {
	case strings.HasSuffix(path, ".ts"):
		return typescript.GetLanguage()
	case strings.HasSuffix(path, ".tsx"):
		return tsx.GetLanguage()
	}
	return javascript.GetLanguage()
}

func walk(n *sitter.Node, src []byte, path string, out *[]rules.Finding) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "call_expression":
		*out = append(*out, evalCall(n, src, path)...)
	case "member_expression":
		*out = append(*out, evalMember(n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, out)
	}
}

// evalCall handles obj.method("arg", …) crypto calls.
func evalCall(call *sitter.Node, src []byte, path string) []rules.Finding {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "member_expression" {
		return nil
	}
	obj := receiverName(fn.ChildByFieldName("object"), src)
	method := fieldText(fn, "property", src)
	if obj == "" || method == "" {
		return nil
	}
	matches := rules.JSEvaluate(obj, method, firstStringArg(call, src))
	return findingsFrom(matches, call, src, path)
}

// evalMember handles bare member accesses — specifically *.mode.ECB.
func evalMember(node *sitter.Node, src []byte, path string) []rules.Finding {
	if fieldText(node, "property", src) != "ECB" {
		return nil
	}
	obj := node.ChildByFieldName("object")
	if obj == nil || obj.Type() != "member_expression" || fieldText(obj, "property", src) != "mode" {
		return nil
	}
	return findingsFrom(rules.JSEvaluate("mode", "ECB", ""), node, src, path)
}

func findingsFrom(matches []rules.Match, node *sitter.Node, src []byte, path string) []rules.Finding {
	if len(matches) == 0 {
		return nil
	}
	pt := node.StartPoint()
	out := make([]rules.Finding, 0, len(matches))
	for _, m := range matches {
		out = append(out, rules.Finding{
			Match: m, File: path,
			Line: int(pt.Row) + 1, Column: int(pt.Column) + 1, Evidence: snippet(node, src),
		})
	}
	return out
}

// receiverName is the identifier name of a call receiver, or — for a member
// receiver like CryptoJS.mode — its trailing property name.
func receiverName(n *sitter.Node, src []byte) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case "identifier":
		return n.Content(src)
	case "member_expression":
		return fieldText(n, "property", src)
	}
	return ""
}

func fieldText(n *sitter.Node, field string, src []byte) string {
	if c := n.ChildByFieldName(field); c != nil {
		return c.Content(src)
	}
	return ""
}

// firstStringArg returns the value of the first string-literal argument, if any.
func firstStringArg(call *sitter.Node, src []byte) string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return ""
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if a := args.NamedChild(i); a.Type() == "string" {
			for j := 0; j < int(a.NamedChildCount()); j++ {
				if part := a.NamedChild(j); part.Type() == "string_fragment" {
					return part.Content(src)
				}
			}
			return "" // empty string literal
		}
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
