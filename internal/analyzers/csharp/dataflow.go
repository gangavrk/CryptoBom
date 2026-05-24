package csharp

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// dataflow holds a lightweight intra-procedural taint set: variables filled by a
// non-cryptographic PRNG (System.Random.NextBytes). Keyed by (enclosing method,
// variable). RandomNumberGenerator / RNGCryptoServiceProvider are the secure RNGs
// and use GetBytes, so they're never matched here.
type dataflow struct {
	weakRandom map[string]bool
}

func buildDataflow(root *sitter.Node, src []byte) *dataflow {
	df := &dataflow{weakRandom: map[string]bool{}}
	randomVar := map[string]bool{}

	// Pass 1: `var r = new Random()` bindings.
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "variable_declarator" {
			return
		}
		name := n.ChildByFieldName("name")
		value := lastNamedChild(n)
		if name != nil && isNewRandom(value, src) {
			randomVar[varKey(enclosingScope(n), name.Content(src))] = true
		}
	})

	// Pass 2: `r.NextBytes(buf)` taints buf.
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "invocation_expression" {
			return
		}
		fn := n.ChildByFieldName("function")
		if fn == nil || fn.Type() != "member_access_expression" {
			return
		}
		nm := fn.ChildByFieldName("name")
		if nm == nil || nm.Content(src) != "NextBytes" {
			return
		}
		if !isWeakReceiver(fn.ChildByFieldName("expression"), src, randomVar, enclosingScope(n)) {
			return
		}
		args := argExprs(n)
		if len(args) > 0 && args[0] != nil && args[0].Type() == "identifier" {
			df.weakRandom[varKey(enclosingScope(n), args[0].Content(src))] = true
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

func isNewRandom(n *sitter.Node, src []byte) bool {
	if n == nil || n.Type() != "object_creation_expression" {
		return false
	}
	t := n.ChildByFieldName("type")
	return t != nil && afterLastDot(t.Content(src)) == "Random"
}

func isWeakReceiver(recv *sitter.Node, src []byte, randomVar map[string]bool, scope uint32) bool {
	if recv == nil {
		return false
	}
	switch recv.Type() {
	case "identifier":
		return randomVar[varKey(scope, recv.Content(src))]
	case "object_creation_expression": // inline new Random().NextBytes(buf)
		return isNewRandom(recv, src)
	}
	return false
}

func enclosingScope(n *sitter.Node) uint32 {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "method_declaration", "constructor_declaration", "local_function_statement":
			return p.StartByte()
		}
	}
	return 0
}

func lastNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(int(n.NamedChildCount()) - 1)
}
