// Package cfamily detects cryptographic usage in C and C++ via tree-sitter,
// targeting OpenSSL (the dominant C crypto library): function-name-encoded
// algorithms (EVP_des_ede3_cbc, MD5, RSA_generate_key_ex), the 3.0 fetch API
// (EVP_MD_fetch("MD5")), TLS method constructors, and version constants.
package cfamily

import (
	"context"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	cgrammar "github.com/smacker/go-tree-sitter/c"
	"github.com/smacker/go-tree-sitter/cpp"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses C/C++ source and returns crypto findings located in path.
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
	for _, ext := range []string{".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"} {
		if strings.HasSuffix(path, ext) {
			return cpp.GetLanguage()
		}
	}
	return cgrammar.GetLanguage()
}

func walk(n *sitter.Node, src []byte, path string, out *[]rules.Finding) {
	if n == nil {
		return
	}
	switch n.Type() {
	case "call_expression":
		*out = append(*out, evalCall(n, src, path)...)
	case "identifier":
		// OpenSSL version constants used as arguments (TLS1_1_VERSION, …).
		*out = append(*out, findingsFrom(rules.CVersionConst(n.Content(src)), n, src, path)...)
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), src, path, out)
	}
}

func evalCall(call *sitter.Node, src []byte, path string) []rules.Finding {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Type() != "identifier" {
		return nil
	}
	matches := rules.CEvaluate(fn.Content(src), firstStringArg(call, src))
	return findingsFrom(matches, call, src, path)
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

func firstStringArg(call *sitter.Node, src []byte) string {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return ""
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if a := args.NamedChild(i); a.Type() == "string_literal" {
			for j := 0; j < int(a.NamedChildCount()); j++ {
				if part := a.NamedChild(j); part.Type() == "string_content" {
					return part.Content(src)
				}
			}
			return ""
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
