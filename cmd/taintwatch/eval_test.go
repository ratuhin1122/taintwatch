package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvalValidateCLI(t *testing.T) {
	home := filepath.Join(t.TempDir(), "no-state")
	t.Setenv("TAINTWATCH_HOME", home)
	var out, errout bytes.Buffer
	if code := run([]string{"eval", "validate", "../../eval/corpus"}, strings.NewReader(""), &out, &errout); code != 0 || errout.Len() != 0 || !strings.Contains(out.String(), "74 scenarios (35 attacks, 39 benign)") || !strings.Contains(out.String(), "Validation only") {
		t.Fatal(code, out.String(), errout.String())
	}
	if _, err := os.Stat(home); !os.IsNotExist(err) {
		t.Fatal("validator created state", err)
	}
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"eval", "replay"}, 2}, {[]string{"eval", "validate", "--unknown"}, 2}, {[]string{"eval", "validate", "a", "b"}, 2}, {[]string{"eval", "validate", filepath.Join(t.TempDir(), "missing")}, 1},
		{[]string{"eval", "run", "--json", "--markdown"}, 2}, {[]string{"eval", "run", "--unknown"}, 2},
	} {
		out.Reset()
		errout.Reset()
		if code := run(tc.args, strings.NewReader(""), &out, &errout); code != tc.code || out.Len() != 0 || errout.Len() == 0 {
			t.Fatal(tc.args, code, out.String(), errout.String())
		}
	}
	for _, args := range [][]string{{"eval", "--help"}, {"eval", "validate", "--help"}} {
		out.Reset()
		errout.Reset()
		if code := run(args, strings.NewReader(""), &out, &errout); code != 0 || !strings.Contains(out.String(), "Usage:") || errout.Len() != 0 {
			t.Fatal(code, out.String(), errout.String())
		}
	}
}
