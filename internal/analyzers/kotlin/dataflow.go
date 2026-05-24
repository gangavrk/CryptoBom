package kotlin

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// dataflow holds a lightweight intra-procedural pass over a Kotlin file: key sizes
// attached to KeyPairGenerator variables and variables holding non-cryptographic
// PRNG output. Keyed by (enclosing function, variable).
type dataflow struct {
	keySize    map[string]int  // var -> bits, from kpg.initialize(n)
	weakRandom map[string]bool // var -> filled by Random().nextBytes(var)
}

func buildDataflow(root *sitter.Node, src []byte) *dataflow {
	df := &dataflow{keySize: map[string]int{}, weakRandom: map[string]bool{}}
	randomVar := map[string]bool{}

	// Pass 1: `val r = Random()` bindings (not SecureRandom).
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "property_declaration" {
			return
		}
		name := propertyName(n, src)
		val := propertyValue(n)
		if name == "" || val == nil || val.Type() != "call_expression" {
			return
		}
		if callee := firstNamedChild(val); callee != nil && callee.Type() == "simple_identifier" &&
			isWeakRandomType(callee.Content(src)) {
			randomVar[varKey(enclosingScope(n), name)] = true
		}
	})

	// Pass 2: initialize(bits) key sizes and nextBytes() weak-random targets.
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "call_expression" {
			return
		}
		callee := firstNamedChild(n)
		if callee == nil || callee.Type() != "navigation_expression" {
			return
		}
		recv := navReceiver(callee)
		args := argExprs(n)
		switch navMethod(callee, src) {
		case "initialize":
			if recv != nil && recv.Type() == "simple_identifier" && len(args) > 0 {
				if v, ok := intOf(args[0], src); ok {
					df.keySize[varKey(enclosingScope(n), recv.Content(src))] = v
				}
			}
		case "nextBytes":
			if isWeakReceiver(recv, src, randomVar, enclosingScope(n)) &&
				len(args) > 0 && args[0] != nil && args[0].Type() == "simple_identifier" {
				df.weakRandom[varKey(enclosingScope(n), args[0].Content(src))] = true
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

// propertyName returns the variable name declared in a property_declaration.
func propertyName(pd *sitter.Node, src []byte) string {
	if vd := childOfType(pd, "variable_declaration"); vd != nil {
		if id := childOfType(vd, "simple_identifier"); id != nil {
			return id.Content(src)
		}
	}
	return ""
}

// propertyValue returns the initializer expression of a property_declaration.
func propertyValue(pd *sitter.Node) *sitter.Node {
	return lastNamedChild(pd)
}

func enclosingScope(n *sitter.Node) uint32 {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Type() == "function_declaration" {
			return p.StartByte()
		}
	}
	return 0
}

// isWeakRandomType matches kotlin.random.Random / java.util.Random, not SecureRandom.
func isWeakRandomType(name string) bool { return name == "Random" }

func isWeakReceiver(recv *sitter.Node, src []byte, randomVar map[string]bool, scope uint32) bool {
	if recv == nil {
		return false
	}
	switch recv.Type() {
	case "simple_identifier":
		return randomVar[varKey(scope, recv.Content(src))]
	case "call_expression": // inline Random().nextBytes(buf)
		if callee := firstNamedChild(recv); callee != nil && callee.Type() == "simple_identifier" {
			return isWeakRandomType(callee.Content(src))
		}
	}
	return false
}

func intOf(n *sitter.Node, src []byte) (int, bool) {
	if n == nil || n.Type() != "integer_literal" {
		return 0, false
	}
	v := 0
	for _, r := range n.Content(src) {
		if r == '_' {
			continue
		}
		if r < '0' || r > '9' {
			return 0, false
		}
		v = v*10 + int(r-'0')
	}
	return v, true
}
