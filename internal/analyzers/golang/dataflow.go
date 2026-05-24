package golang

import (
	"fmt"
	"go/ast"
	"go/token"
	"strings"
)

// dataflow holds lightweight intra-procedural taint sets keyed by (enclosing func,
// variable): `weak` for bytes from a non-cryptographic PRNG (math/rand), and `mac`
// for values that hold a MAC/digest. Scoping avoids cross-function name collisions.
type dataflow struct {
	funcs []*ast.FuncDecl
	weak  map[string]bool
	mac   map[string]bool
}

func buildDataflow(file *ast.File, imports map[string]string) *dataflow {
	df := &dataflow{weak: map[string]bool{}, mac: map[string]bool{}}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			df.funcs = append(df.funcs, fd)
		}
	}

	hasher := map[string]bool{} // vars from hmac.New(...)

	// Pass 1: weak-PRNG fills and hmac.New hasher bindings.
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok {
					if isMathRand(imports[pkg.Name]) && sel.Sel.Name == "Read" && len(call.Args) >= 1 {
						if id, ok := call.Args[0].(*ast.Ident); ok {
							df.weak[df.key(id.Pos(), id.Name)] = true
						}
					}
				}
			}
		}
		forEachAssign(n, func(lhs *ast.Ident, rhs ast.Expr) {
			if call, ok := rhs.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if pkg, ok := sel.X.(*ast.Ident); ok &&
						imports[pkg.Name] == "crypto/hmac" && sel.Sel.Name == "New" {
						hasher[df.key(lhs.Pos(), lhs.Name)] = true
					}
				}
			}
		})
		return true
	})

	// Pass 2: MAC/digest tags from hasher.Sum(...) or <hashpkg>.Sum*(...).
	ast.Inspect(file, func(n ast.Node) bool {
		forEachAssign(n, func(lhs *ast.Ident, rhs ast.Expr) {
			call, ok := rhs.(*ast.CallExpr)
			if !ok {
				return
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return
			}
			if (hasher[df.key(x.Pos(), x.Name)] && sel.Sel.Name == "Sum") ||
				isHashSumFunc(imports[x.Name], sel.Sel.Name) {
				df.mac[df.key(lhs.Pos(), lhs.Name)] = true
			}
		})
		return true
	})
	return df
}

// forEachAssign invokes fn for each (ident, value) binding in `:=`/`=` statements
// and `var` declarations.
func forEachAssign(n ast.Node, fn func(lhs *ast.Ident, rhs ast.Expr)) {
	switch s := n.(type) {
	case *ast.AssignStmt:
		for i := 0; i < len(s.Lhs) && i < len(s.Rhs); i++ {
			if id, ok := s.Lhs[i].(*ast.Ident); ok {
				fn(id, s.Rhs[i])
			}
		}
	case *ast.ValueSpec:
		for i := 0; i < len(s.Names) && i < len(s.Values); i++ {
			fn(s.Names[i], s.Values[i])
		}
	}
}

func isHashSumFunc(path, fn string) bool {
	switch path {
	case "crypto/sha256", "crypto/sha512":
		return strings.HasPrefix(fn, "Sum")
	case "crypto/sha1", "crypto/md5":
		return fn == "Sum"
	}
	return false
}

// tainted reports whether arg is an identifier holding non-cryptographic randomness.
func (df *dataflow) tainted(arg ast.Expr) bool {
	id, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	return df.weak[df.key(id.Pos(), id.Name)]
}

// taintedMac reports whether arg is an identifier holding a MAC/digest value.
func (df *dataflow) taintedMac(arg ast.Expr) bool {
	id, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	return df.mac[df.key(id.Pos(), id.Name)]
}

func (df *dataflow) key(pos token.Pos, name string) string {
	return fmt.Sprintf("%d:%s", df.enclosingFunc(pos), name)
}

func (df *dataflow) enclosingFunc(pos token.Pos) token.Pos {
	for _, fd := range df.funcs {
		if fd.Pos() <= pos && pos <= fd.End() {
			return fd.Pos()
		}
	}
	return token.NoPos
}

func isMathRand(path string) bool {
	return path == "math/rand" || path == "math/rand/v2"
}
