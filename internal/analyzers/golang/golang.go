// Package golang detects cryptographic usage in Go source using the standard
// library's own parser (go/ast). Detection is precise: a call only matches if its
// selector resolves through the file's imports to a known crypto package, so a
// method on an unrelated variable is never mistaken for a crypto call.
package golang

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"github.com/cryptobom/cryptobom/internal/rules"
)

// Analyze parses Go source and returns crypto findings located in filename.
func Analyze(filename string, src []byte) ([]rules.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if file == nil {
		return nil, err // unrecoverable parse failure
	}

	imports := importMap(file)
	df := buildDataflow(file, imports)

	var findings []rules.Finding
	add := func(matches []rules.Match, n ast.Node) {
		pos := fset.Position(n.Pos())
		for _, m := range matches {
			findings = append(findings, rules.Finding{
				Match:    m,
				File:     filename,
				Line:     pos.Line,
				Column:   pos.Column,
				Evidence: snippet(src, fset, n),
			})
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		// Non-constant-time comparison of a MAC/digest with `==` / `!=`.
		if be, ok := n.(*ast.BinaryExpr); ok {
			if (be.Op == token.EQL || be.Op == token.NEQ) &&
				(df.taintedMac(be.X) || df.taintedMac(be.Y)) {
				add([]rules.Match{rules.TimingCompare()}, be)
			}
			return true
		}

		// TLS version constants: tls.VersionTLS10, tls.VersionSSL30, ...
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if pkg, ok := sel.X.(*ast.Ident); ok && imports[pkg.Name] == "crypto/tls" {
				if tok := goTLSConst[sel.Sel.Name]; tok != "" {
					add(rules.EvalProtocol(tok), sel)
				}
			}
			return true
		}

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
		pkgPath, ok := imports[pkgIdent.Name]
		if !ok {
			return true
		}

		matches := rules.GoEvaluate(pkgPath, sel.Sel.Name)
		if bits, curve := keyParams(pkgPath, sel.Sel.Name, call); bits > 0 || curve != "" {
			matches = rules.AnnotateKey(matches, bits, curve)
		}
		matches = append(matches, goMisuse(pkgPath, sel.Sel.Name, call, df)...)
		matches = append(matches, goTimingSink(pkgPath, sel.Sel.Name, call, df)...)
		add(matches, call)
		return true
	})
	return findings, nil
}

// goTLSConst maps crypto/tls version constants to a protocol token.
var goTLSConst = map[string]string{
	"VersionSSL30": "SSLv3",
	"VersionTLS10": "TLSv1.0",
	"VersionTLS11": "TLSv1.1",
	"VersionTLS12": "TLSv1.2",
	"VersionTLS13": "TLSv1.3",
}

// goTimingSink flags bytes.Equal / reflect.DeepEqual on a MAC/digest operand.
func goTimingSink(pkgPath, fn string, call *ast.CallExpr, df *dataflow) []rules.Match {
	timing := (pkgPath == "bytes" && fn == "Equal") || (pkgPath == "reflect" && fn == "DeepEqual")
	if timing && len(call.Args) >= 2 && (df.taintedMac(call.Args[0]) || df.taintedMac(call.Args[1])) {
		return []rules.Match{rules.TimingCompare()}
	}
	return nil
}

var goStaticIVFuncs = map[string]bool{
	"NewCBCEncrypter": true, "NewCBCDecrypter": true, "NewCTR": true,
	"NewOFB": true, "NewCFBEncrypter": true, "NewCFBDecrypter": true,
}

// goMisuse flags hardcoded keys / static IVs (a literal passed where a key/IV is
// expected) and weak-PRNG key/IV material (a value filled by math/rand reaching the
// same key/IV slot).
func goMisuse(pkgPath, fn string, call *ast.CallExpr, df *dataflow) []rules.Match {
	switch pkgPath {
	case "crypto/aes", "crypto/des", "crypto/rc4":
		if (fn == "NewCipher" || fn == "NewTripleDESCipher") && len(call.Args) >= 1 {
			switch {
			case isLiteralBytes(call.Args[0]):
				return []rules.Match{rules.HardcodedKey(goCipherName(pkgPath, fn))}
			case df.tainted(call.Args[0]):
				return []rules.Match{rules.WeakPRNG(goCipherName(pkgPath, fn))}
			}
		}
	case "crypto/cipher":
		if goStaticIVFuncs[fn] && len(call.Args) >= 2 {
			switch {
			case isLiteralBytes(call.Args[1]):
				return []rules.Match{rules.StaticIV("")}
			case df.tainted(call.Args[1]):
				return []rules.Match{rules.WeakPRNG("")}
			}
		}
	}
	return nil
}

// isLiteralBytes reports whether e is a string literal or a []byte("...") conversion.
func isLiteralBytes(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.CallExpr:
		if _, ok := x.Fun.(*ast.ArrayType); ok && len(x.Args) == 1 {
			if lit, ok := x.Args[0].(*ast.BasicLit); ok {
				return lit.Kind == token.STRING
			}
		}
	}
	return false
}

func goCipherName(pkgPath, fn string) string {
	switch pkgPath {
	case "crypto/aes":
		return "AES"
	case "crypto/rc4":
		return "RC4"
	case "crypto/des":
		if fn == "NewTripleDESCipher" {
			return "3DES"
		}
		return "DES"
	}
	return ""
}

// keyParams extracts an asymmetric key size or curve from a keygen call.
func keyParams(pkgPath, fn string, call *ast.CallExpr) (bits int, curve string) {
	switch {
	case pkgPath == "crypto/rsa" && fn == "GenerateKey":
		return singleIntArg(call), ""
	case pkgPath == "crypto/ecdsa" && fn == "GenerateKey":
		return 0, firstCurveArg(call)
	}
	return 0, ""
}

// singleIntArg returns the value of the sole integer-literal argument, or 0 when
// there is not exactly one (avoids guessing among multiple ints).
func singleIntArg(call *ast.CallExpr) int {
	found, n := 0, 0
	for _, a := range call.Args {
		if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.INT {
			if v, err := strconv.Atoi(lit.Value); err == nil {
				found, n = v, n+1
			}
		}
	}
	if n == 1 {
		return found
	}
	return 0
}

// firstCurveArg returns the curve name from a leading elliptic.P256()-style arg.
func firstCurveArg(call *ast.CallExpr) string {
	if len(call.Args) == 0 {
		return ""
	}
	switch a := call.Args[0].(type) {
	case *ast.CallExpr:
		if se, ok := a.Fun.(*ast.SelectorExpr); ok {
			return se.Sel.Name
		}
	case *ast.SelectorExpr:
		return a.Sel.Name
	}
	return ""
}

// importMap maps each import's local name to its package path, skipping blank
// and dot imports (calls through those can't be attributed to a package name).
func importMap(file *ast.File) map[string]string {
	m := make(map[string]string, len(file.Imports))
	for _, imp := range file.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		name := path[strings.LastIndex(path, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" || name == "." {
			continue
		}
		m[name] = path
	}
	return m
}

func snippet(src []byte, fset *token.FileSet, n ast.Node) string {
	start := fset.Position(n.Pos()).Offset
	end := fset.Position(n.End()).Offset
	if start < 0 || end > len(src) || start >= end {
		return ""
	}
	s := string(src[start:end])
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}
