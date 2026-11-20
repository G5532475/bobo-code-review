// review_scan_go inventories findings in Go source without loading target packages.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
)

type finding struct {
	Line     int    `json:"line"`
	EndLine  int    `json:"end_line"`
	Category string `json:"category"`
	Evidence string `json:"evidence"`
	Severity string `json:"severity"`
}

type result struct {
	Findings []finding `json:"findings"`
	Error    string    `json:"error,omitempty"`
}

var secretName = regexp.MustCompile("(?i)^(api_?key|secret|password|access_key|secret_key|token|ak|sk)$")
var secretValue = regexp.MustCompile("^[A-Za-z0-9_-]{16,}$")
var errorName = regexp.MustCompile("^(err|error|err[_A-Z].*|.*(Err|Error|_err|_error))$")
var methods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "PATCH": true,
	"HEAD": true, "OPTIONS": true, "CONNECT": true, "TRACE": true, "Any": true,
}

type scan struct {
	imports map[string]string
	routers map[*ast.Object]string
}

func literal(expr ast.Expr) string {
	val, ok := expr.(*ast.BasicLit)
	if !ok || val.Kind != token.STRING {
		return ""
	}
	value, _ := strconv.Unquote(val.Value)
	return value
}

func (s scan) packageOf(expr ast.Expr) string {
	id, ok := expr.(*ast.Ident)
	if ok && id.Obj == nil {
		return s.imports[id.Name]
	}
	return ""
}

func (s scan) routerOf(expr ast.Expr) string {
	switch expr := expr.(type) {
	case *ast.Ident:
		return s.routers[expr.Obj]
	case *ast.StarExpr:
		return s.routerOf(expr.X)
	case *ast.CallExpr:
		fn, ok := expr.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		switch s.packageOf(fn.X) {
		case "net_http":
			if fn.Sel.Name == "NewServeMux" {
				return "net_http"
			}
		case "gin":
			if fn.Sel.Name == "New" || fn.Sel.Name == "Default" {
				return "gin"
			}
		case "echo":
			if fn.Sel.Name == "New" {
				return "echo"
			}
		}
		if fn.Sel.Name == "Group" {
			return s.routerOf(fn.X)
		}
	case *ast.SelectorExpr:
		fw := s.packageOf(expr.X)
		name := expr.Sel.Name
		switch {
		case fw == "net_http" && (name == "ServeMux" || name == "DefaultServeMux"):
			return fw
		case fw == "gin" && (name == "Engine" || name == "RouterGroup" || name == "IRoutes" || name == "IRouter"):
			return fw
		case fw == "echo" && (name == "Echo" || name == "Group"):
			return fw
		}
	}
	return ""
}

func (s scan) route(call *ast.CallExpr) string {
	fn, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || len(call.Args) < 2 {
		return ""
	}
	method := fn.Sel.Name
	framework := s.routerOf(fn.X)
	if s.packageOf(fn.X) == "net_http" {
		framework = "net_http"
	}
	var route string
	switch framework {
	case "net_http":
		if method != "Handle" && method != "HandleFunc" {
			return ""
		}
		route = literal(call.Args[0])
		if before, after, found := strings.Cut(route, " "); found {
			method, route = before, after
		}
	case "gin", "echo":
		if (framework == "gin" && method == "Handle") || (framework == "echo" && method == "Add") {
			if len(call.Args) < 3 {
				return ""
			}
			method = literal(call.Args[0])
			if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && s.packageOf(sel.X) == "net_http" {
				if suffix, ok := strings.CutPrefix(sel.Sel.Name, "Method"); ok {
					method = strings.ToUpper(suffix)
				}
			}
			route = literal(call.Args[1])
		} else if methods[method] {
			route = literal(call.Args[0])
		}
	}
	if route == "" || method == "" {
		return ""
	}
	return fmt.Sprintf("[%s] %s %s", framework, method, route)
}

func emptyErrorBranch(stmt *ast.IfStmt) string {
	if len(stmt.Body.List) != 0 {
		return ""
	}
	cond, ok := ast.Unparen(stmt.Cond).(*ast.BinaryExpr)
	if !ok || cond.Op != token.NEQ {
		return ""
	}
	left, lok := ast.Unparen(cond.X).(*ast.Ident)
	right, rok := ast.Unparen(cond.Y).(*ast.Ident)
	if !lok || !rok {
		return ""
	}
	if left.Name == "nil" {
		left, right = right, left
	}
	if right.Name == "nil" && errorName.MatchString(left.Name) {
		return left.Name
	}
	return ""
}

func analyze(filename string) result {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, nil, 0)
	if err != nil {
		return result{Error: err.Error()}
	}

	s := scan{imports: make(map[string]string), routers: make(map[*ast.Object]string)}
	for _, spec := range file.Imports {
		name := path.Base(literal(spec.Path))
		fw := ""
		switch literal(spec.Path) {
		case "net/http":
			fw = "net_http"
		case "github.com/gin-gonic/gin":
			fw = "gin"
		case "github.com/labstack/echo", "github.com/labstack/echo/v4", "github.com/labstack/echo/v5":
			name, fw = "echo", "echo"
		}
		if spec.Name != nil {
			name = spec.Name.Name
		}
		if fw != "" {
			s.imports[name] = fw
		}
	}

	out := result{Findings: []finding{}}
	add := func(node ast.Node, category, severity, evidence string) {
		out.Findings = append(out.Findings, finding{
			Line:     fset.PositionFor(node.Pos(), false).Line,
			EndLine:  fset.PositionFor(node.End(), false).Line,
			Category: category, Severity: severity, Evidence: evidence,
		})
	}
	bind := func(node ast.Node, lhs ast.Expr, typ, value ast.Expr) {
		id, ok := lhs.(*ast.Ident)
		if !ok {
			return
		}
		fw := s.routerOf(value)
		if fw == "" {
			fw = s.routerOf(typ)
		}
		if fw != "" && id.Obj != nil {
			s.routers[id.Obj] = fw
		}
		key := literal(value)
		switch key {
		case "your-secret-key-change-in-production-please-use-env-var", "change-me-to-a-random-secret":
			add(node, "secret", "P1", fmt.Sprintf("Placeholder secret default assigned to %s", id.Name))
		default:
			if secretName.MatchString(id.Name) && secretValue.MatchString(key) {
				add(node, "secret", "P0", fmt.Sprintf("Suspected hardcoded secret: %s (len=%d)", id.Name, len(key)))
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		switch node := node.(type) {
		case *ast.Field:
			for _, name := range node.Names {
				bind(node, name, node.Type, nil)
			}
		case *ast.ValueSpec:
			for i, name := range node.Names {
				var value ast.Expr
				if len(node.Values) == len(node.Names) {
					value = node.Values[i]
				}
				bind(node, name, node.Type, value)
			}
		case *ast.AssignStmt:
			if len(node.Lhs) == len(node.Rhs) {
				for i, lhs := range node.Lhs {
					bind(node, lhs, nil, node.Rhs[i])
				}
			}
		case *ast.CallExpr:
			if route := s.route(node); route != "" {
				add(node, "route", "INFO", route)
			}
		case *ast.IfStmt:
			if name := emptyErrorBranch(node); name != "" {
				out.Findings = append(out.Findings, finding{
					Line:     fset.PositionFor(node.Pos(), false).Line,
					EndLine:  fset.PositionFor(node.Body.End(), false).Line,
					Category: "error_swallow", Severity: "P2",
					Evidence: fmt.Sprintf("Go error branch is empty: if %s != nil", name),
				})
			}
		}
		return true
	})
	return out
}

func main() {
	var paths []string
	if err := json.NewDecoder(os.Stdin).Decode(&paths); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	results := make(map[string]result, len(paths))
	for _, filename := range paths {
		results[filename] = analyze(filename)
	}
	if err := json.NewEncoder(os.Stdout).Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
