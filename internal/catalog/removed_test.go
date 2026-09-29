package catalog

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The file catalog and the JSONL audit log are removed: their Open
// functions and the import tool must not come back.
func TestFileStoresStayRemoved(t *testing.T) {
	for _, dir := range []string{".", "../audit"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range file.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "Open" {
					t.Errorf("%s: %s.Open is removed", name, file.Name.Name)
				}
			}
		}
	}
	if _, err := os.Stat(filepath.Join("..", "..", "cmd", "mcpwarden-catalog")); !os.IsNotExist(err) {
		t.Error("cmd/mcpwarden-catalog is removed")
	}
}
