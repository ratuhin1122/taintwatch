//go:build linux || darwin

package rules

import (
	"github.com/ratuhin1122/taintwatch/internal/state"
	"os"
	"path/filepath"
	"testing"
)

func TestPathExceptionSymlinkRetarget(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, ".env.a")
	b := filepath.Join(dir, ".env.b")
	link := filepath.Join(dir, ".env.link")
	for _, f := range []string{a, b} {
		if e := os.WriteFile(f, []byte("private"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink(a, link); e != nil {
		t.Fatal(e)
	}
	canonical, e := filepath.EvalSymlinks(a)
	if e != nil {
		t.Fatal(e)
	}
	p := DefaultPolicy()
	p.AllowedPaths = []string{canonical}
	in := Input{Policy: p, Session: state.Session{Tainted: true}, Tool: "Read", FilePath: link, CWD: dir}
	if d := Evaluate(in); d.Action != Allow {
		t.Fatal(d)
	}
	if e = os.Remove(link); e != nil {
		t.Fatal(e)
	}
	if e = os.Symlink(b, link); e != nil {
		t.Fatal(e)
	}
	if d := Evaluate(in); d.Action != Ask {
		t.Fatal("symlink retarget bypass", d)
	}
}
