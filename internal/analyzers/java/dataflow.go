package java

import (
	"fmt"

	sitter "github.com/smacker/go-tree-sitter"
)

// dataflow holds the results of a lightweight intra-procedural pass over a file:
// key sizes attached to KeyPairGenerator variables and variables that hold output
// from a non-cryptographic PRNG. Both are keyed by (enclosing-method, variable).
type dataflow struct {
	keySize    map[string]int  // var -> bits, from kpg.initialize(n)
	weakRandom map[string]bool // var -> filled by a java.util.Random
	macObj     map[string]bool // var -> a Mac / MessageDigest from getInstance
	macTag     map[string]bool // var -> a MAC/digest value from .doFinal()/.digest()
}

func buildDataflow(root *sitter.Node, src []byte) *dataflow {
	df := &dataflow{
		keySize: map[string]int{}, weakRandom: map[string]bool{},
		macObj: map[string]bool{}, macTag: map[string]bool{},
	}
	randomVar := map[string]bool{} // vars bound to new Random()

	// Pass 1: weak-PRNG bindings and Mac/MessageDigest getInstance bindings.
	walkAll(root, func(n *sitter.Node) {
		name, value := binding(n, src)
		if value != nil && value.Type() == "object_creation_expression" &&
			isWeakRandomType(typeName(value, src)) {
			randomVar[varKey(enclosingScope(n), name)] = true
		}
		if n.Type() == "method_invocation" && callName(n, src) == "getInstance" {
			if obj := n.ChildByFieldName("object"); obj != nil && obj.Type() == "identifier" {
				if cls := obj.Content(src); cls == "Mac" || cls == "MessageDigest" {
					if v := assignedVar(n, src); v != "" {
						df.macObj[varKey(enclosingScope(n), v)] = true
					}
				}
			}
		}
	})

	// Pass 2: initialize(int) key sizes, nextBytes() weak-random, and
	// .doFinal()/.digest() MAC/digest tags.
	walkAll(root, func(n *sitter.Node) {
		if n.Type() != "method_invocation" {
			return
		}
		obj := n.ChildByFieldName("object")
		name := n.ChildByFieldName("name")
		args := n.ChildByFieldName("arguments")
		if name == nil {
			return
		}
		switch name.Content(src) {
		case "initialize": // KeyPairGenerator.initialize(bits) — unambiguous
			if obj != nil && obj.Type() == "identifier" {
				if v, ok := leafInt(firstNamedChild(args), src); ok {
					df.keySize[varKey(enclosingScope(n), obj.Content(src))] = v
				}
			}
		case "nextBytes":
			if isWeakReceiver(obj, src, randomVar, enclosingScope(n)) {
				if a := firstNamedChild(args); a != nil && a.Type() == "identifier" {
					df.weakRandom[varKey(enclosingScope(n), a.Content(src))] = true
				}
			}
		case "doFinal", "digest":
			if obj != nil && obj.Type() == "identifier" &&
				df.macObj[varKey(enclosingScope(n), obj.Content(src))] {
				if v := assignedVar(n, src); v != "" {
					df.macTag[varKey(enclosingScope(n), v)] = true
				}
			}
		}
	})
	return df
}

func callName(n *sitter.Node, src []byte) string {
	if name := n.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	return ""
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

// binding returns the declared/assigned variable name and its initializer value.
func binding(n *sitter.Node, src []byte) (string, *sitter.Node) {
	switch n.Type() {
	case "variable_declarator":
		if name := n.ChildByFieldName("name"); name != nil {
			return name.Content(src), n.ChildByFieldName("value")
		}
	case "assignment_expression":
		if left := n.ChildByFieldName("left"); left != nil && left.Type() == "identifier" {
			return left.Content(src), n.ChildByFieldName("right")
		}
	}
	return "", nil
}

// enclosingScope identifies the nearest enclosing method/constructor by start
// byte, so identically named locals in different methods don't collide.
func enclosingScope(n *sitter.Node) uint32 {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "method_declaration", "constructor_declaration",
			"static_initializer", "lambda_expression":
			return p.StartByte()
		}
	}
	return 0
}

func varKey(scope uint32, name string) string {
	return fmt.Sprintf("%d:%s", scope, name)
}

func typeName(objCreation *sitter.Node, src []byte) string {
	if t := objCreation.ChildByFieldName("type"); t != nil {
		return afterLastDot(t.Content(src))
	}
	return ""
}

// isWeakRandomType matches java.util.Random but not SecureRandom.
func isWeakRandomType(t string) bool { return t == "Random" }

func isWeakReceiver(obj *sitter.Node, src []byte, randomVar map[string]bool, scope uint32) bool {
	if obj == nil {
		return false
	}
	switch obj.Type() {
	case "identifier":
		return randomVar[varKey(scope, obj.Content(src))]
	case "object_creation_expression":
		return isWeakRandomType(typeName(obj, src))
	}
	return false
}

func firstNamedChild(n *sitter.Node) *sitter.Node {
	if n == nil || n.NamedChildCount() == 0 {
		return nil
	}
	return n.NamedChild(0)
}

// leafInt parses a node that is a plain integer literal (a digits-only leaf).
func leafInt(n *sitter.Node, src []byte) (int, bool) {
	if n == nil || n.NamedChildCount() != 0 {
		return 0, false
	}
	s := n.Content(src)
	if s == "" {
		return 0, false
	}
	v := 0
	for _, r := range s {
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
