package csharp

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// dataflow holds lightweight intra-procedural taint sets keyed by (enclosing method,
// variable): `weakRandom` for bytes from System.Random.NextBytes, `macObj` for HMAC/
// hash objects, and `macTag` for MAC/digest values. RandomNumberGenerator uses
// GetBytes (not NextBytes) and is never matched as weak.
type dataflow struct {
	weakRandom map[string]bool
	macObj     map[string]bool
	macTag     map[string]bool
}

func buildDataflow(root *sitter.Node, src []byte) *dataflow {
	df := &dataflow{weakRandom: map[string]bool{}, macObj: map[string]bool{}, macTag: map[string]bool{}}
	randomVar := map[string]bool{}

	// Pass 1: `var r = new Random()` and HMAC/hash object bindings.
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "variable_declarator" {
			return
		}
		name := n.ChildByFieldName("name")
		value := lastNamedChild(n)
		if name == nil {
			return
		}
		scope := enclosingScope(n)
		if isNewRandom(value, src) {
			randomVar[varKey(scope, name.Content(src))] = true
		}
		if isHashCtor(value, src) {
			df.macObj[varKey(scope, name.Content(src))] = true
		}
	})

	// Pass 2: NextBytes() weak-random taints and ComputeHash/HashData MAC tags.
	walkAll(root, func(n *sitter.Node) {
		switch n.Type() {
		case "invocation_expression":
			recv, method := invRecvMethod(n, src)
			if method == "NextBytes" && isWeakReceiver(recv, src, randomVar, enclosingScope(n)) {
				args := argExprs(n)
				if len(args) > 0 && args[0] != nil && args[0].Type() == "identifier" {
					df.weakRandom[varKey(enclosingScope(n), args[0].Content(src))] = true
				}
			}
		case "variable_declarator":
			name := n.ChildByFieldName("name")
			value := lastNamedChild(n)
			if name != nil && isMacProducingCall(value, src, df, enclosingScope(n)) {
				df.macTag[varKey(enclosingScope(n), name.Content(src))] = true
			}
		}
	})
	return df
}

// isHashCtor reports whether n constructs/creates an HMAC or hash object.
func isHashCtor(n *sitter.Node, src []byte) bool {
	if n == nil {
		return false
	}
	switch n.Type() {
	case "object_creation_expression":
		if t := n.ChildByFieldName("type"); t != nil {
			return isHashOrHmac(afterLastDot(t.Content(src)))
		}
	case "invocation_expression":
		recv, method := invRecvMethod(n, src)
		if method == "Create" && recv != nil && recv.Type() == "identifier" {
			return isHashOrHmac(recv.Content(src))
		}
	}
	return false
}

// isMacProducingCall reports whether n is macObjVar.ComputeHash(...) or a static
// <HashType>.HashData(...) call — i.e. it yields a MAC/digest value.
func isMacProducingCall(n *sitter.Node, src []byte, df *dataflow, scope uint32) bool {
	if n == nil || n.Type() != "invocation_expression" {
		return false
	}
	recv, method := invRecvMethod(n, src)
	if recv == nil || recv.Type() != "identifier" {
		return false
	}
	switch method {
	case "ComputeHash", "TransformFinalBlock":
		return df.macObj[varKey(scope, recv.Content(src))]
	case "HashData":
		return isHashOrHmac(recv.Content(src))
	}
	return false
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
