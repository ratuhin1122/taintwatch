package main

import (
	"bytes"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfirmation(t *testing.T) {
	for _, tc := range []struct {
		answer            string
		yes, terminal, ok bool
	}{{"y\n", false, false, false}, {"\n", false, true, false}, {"n\n", false, true, false}, {"y\n", false, true, true}, {"yes\n", false, true, true}, {"", true, false, true}} {
		var out bytes.Buffer
		e := confirmChange(strings.NewReader(tc.answer), &out, tc.yes, tc.terminal)
		if (e == nil) != tc.ok {
			t.Fatal(tc, e)
		}
	}
}
func TestAllowCLI(t *testing.T) {
	p := operatorHome(t)
	var out, errOut bytes.Buffer
	if code := run([]string{"allow", "domain", "example.com"}, strings.NewReader("y\n"), &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "non-interactive") || !strings.Contains(out.String(), "+++ ") {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("silent policy edit", e)
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"allow", "domain", "example.com", "--yes"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	loaded, e := policy.Load(policy.Options{NoProject: true})
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, host := range loaded.Config.Egress.AllowDomains {
		found = found || host == "example.com"
	}
	if !found {
		t.Fatal("not allowed")
	}
	if code := run([]string{"disallow", "domain", "example.com", "--yes"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
	for _, name := range []string{"allow", "disallow", "clear"} {
		out.Reset()
		errOut.Reset()
		if code := run([]string{name, "--help"}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.Contains(out.String(), "Usage:") {
			t.Fatal(name, code, out.String())
		}
	}
}
func TestClearRequiresReason(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"clear", "--session", "s"}, strings.NewReader(""), &out, &errOut)
	if code != 2 || !strings.Contains(errOut.String(), "--reason") {
		t.Fatal(code, errOut.String())
	}
}
func TestAllowPathCLI(t *testing.T) {
	operatorHome(t)
	file := filepath.Join(t.TempDir(), ".env")
	if e := os.WriteFile(file, []byte("private"), 0600); e != nil {
		t.Fatal(e)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"allow", "path", file, "--yes"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatal(code, errOut.String())
	}
}
