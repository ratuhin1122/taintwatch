package rules

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func TestPathAliases(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, "private")
	if e := os.MkdirAll(filepath.Join(private, "nested"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(private, ".env"), []byte("fixture"), 0600); e != nil {
		t.Fatal(e)
	}
	link := filepath.Join(root, "alias")
	if e := os.Symlink(filepath.Join(private, "nested"), link); e != nil {
		t.Skip("symlink unavailable:", e)
	}
	// The literal spelling cleans to root/.env, but the kernel target is private/.env.
	alias := link + string(os.PathSeparator) + ".." + string(os.PathSeparator) + ".env"
	for _, p := range []string{alias, "private/nested/../.env"} {
		d := Evaluate(Input{Policy: DefaultPolicy(), Session: state.Session{Tainted: true}, CWD: root, Tool: "Read", FilePath: p})
		if d.RuleID != "TW001" {
			t.Fatalf("%s: %+v", p, d)
		}
	}
	target := filepath.Join(root, "CLAUDE.md")
	if e := os.WriteFile(target, nil, 0600); e != nil {
		t.Fatal(e)
	}
	protectedAlias := filepath.Join(root, "ordinary.txt")
	if e := os.Symlink(target, protectedAlias); e != nil {
		t.Fatal(e)
	}
	d := Evaluate(Input{Policy: DefaultPolicy(), Session: state.Session{Tainted: true}, CWD: root, Tool: "Edit", FilePath: protectedAlias})
	if d.RuleID != "TW005" {
		t.Fatalf("%+v", d)
	}
}
