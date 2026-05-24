package python

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// dataflow holds a lightweight intra-procedural taint set: variables assigned from
// the non-cryptographic `random` module. Keyed by (enclosing function, variable) so
// identically named locals in different functions don't collide.
type dataflow struct {
	weakRandom map[string]bool
	macTag     map[string]bool
}

func buildDataflow(root *sitter.Node, src []byte) *dataflow {
	df := &dataflow{weakRandom: map[string]bool{}, macTag: map[string]bool{}}
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "assignment" {
			return
		}
		left := n.ChildByFieldName("left")
		right := n.ChildByFieldName("right")
		if left == nil || left.Type() != "identifier" || right == nil {
			return
		}
		scope := enclosingScope(n)
		if right.Type() == "call" {
			if fn := right.ChildByFieldName("function"); fn != nil && fn.Type() == "attribute" &&
				simpleName(fn.ChildByFieldName("object"), src) == "random" {
				df.weakRandom[varKey(scope, left.Content(src))] = true
			}
			if isMacSourceCall(right, src) {
				df.macTag[varKey(scope, left.Content(src))] = true
			}
		}
	})
	return df
}

func walkAll(n *sitter.Node, fn func(*sitter.Node)) {
	if n == nil {
		return
	}
	fn(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walkAll(n.NamedChild(i), fn)
	}
}

// enclosingScope identifies the nearest enclosing function by start byte (0 for
// module scope), so identically named locals in different functions don't collide.
func enclosingScope(n *sitter.Node) uint32 {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "function_definition" {
			return p.StartByte()
		}
	}
	return 0
}

func varKey(scope uint32, name string) string {
	return fmt.Sprintf("%d:%s", scope, name)
}
