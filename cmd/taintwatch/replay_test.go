package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplayCLI(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "replay")
	var out, errout bytes.Buffer
	args := []string{"replay", "--log", filepath.Join(root, "audit.jsonl"), "--policy", filepath.Join(root, "candidate.yaml")}
	if code := run(args, strings.NewReader(""), &out, &errout); code != 0 || errout.Len() != 0 {
		t.Fatal(code, out.String(), errout.String())
	}
	want, e := os.ReadFile(filepath.Join(root, "candidate.golden"))
	if e != nil || !bytes.Equal(out.Bytes(), want) {
		t.Fatal(out.String(), e)
	}
	for _, args := range [][]string{{"replay"}, {"replay", "--log", "missing"}, {"replay", "--bad"}, {"replay", "--log", "a", "--policy", "b", "extra"}} {
		out.Reset()
		errout.Reset()
		if code := run(args, strings.NewReader(""), &out, &errout); code != 2 || out.Len() != 0 {
			t.Fatal(code, out.String(), errout.String())
		}
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"replay", "--log", "missing", "--policy", filepath.Join(root, "candidate.yaml")}, strings.NewReader(""), &out, &errout); code != 1 || out.Len() != 0 || errout.Len() == 0 {
		t.Fatal(code, out.String(), errout.String())
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"replay", "--help"}, strings.NewReader(""), &out, &errout); code != 0 || !strings.Contains(out.String(), "Usage:") || errout.Len() != 0 {
		t.Fatal(code, out.String(), errout.String())
	}
}
