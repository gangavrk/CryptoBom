package golang

import (
	"fmt"
	"go/ast"
	"go/token"
)

// dataflow holds a lightweight intra-procedural taint set: variables whose bytes
// were filled by a non-cryptographic PRNG (math/rand). Keyed by (enclosing func,
// variable) so identically named locals in different functions don't collide.
type dataflow struct {
	funcs []*ast.FuncDecl
	weak  map[string]bool
}

func buildDataflow(file *ast.File, imports map[string]string) *dataflow {
	df := &dataflow{weak: map[string]bool{}}
	for _, d := range file.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok {
			df.funcs = append(df.funcs, fd)
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		// math/rand.Read(buf) fills buf with non-cryptographic randomness.
		if isMathRand(imports[pkgIdent.Name]) && sel.Sel.Name == "Read" && len(call.Args) >= 1 {
			if id, ok := call.Args[0].(*ast.Ident); ok {
				df.weak[df.key(id.Pos(), id.Name)] = true
			}
		}
		return true
	})
	return df
}

// tainted reports whether arg is an identifier holding non-cryptographic randomness.
func (df *dataflow) tainted(arg ast.Expr) bool {
	id, ok := arg.(*ast.Ident)
	if !ok {
		return false
	}
	return df.weak[df.key(id.Pos(), id.Name)]
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
