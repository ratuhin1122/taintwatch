//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorCommandGolden(t *testing.T) {
	operatorHome(t)
	root := t.TempDir()
	t.Setenv("TAINTWATCH_HOME", filepath.Join(root, "absent"))
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(root, "claude"))
	t.Setenv("CLAUDE_PLUGIN_ROOT", "")
	t.Setenv("PATH", root)
	if e := os.WriteFile(filepath.Join(root, "claude"), []byte("#!/bin/sh\nprintf '2.1.175 (Claude Code)\\n'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	old := version
	version = "0.1.0"
	t.Cleanup(func() { version = old })
	var out, errOut bytes.Buffer
	if code := run([]string{"doctor"}, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() != 0 {
		t.Fatalf("%d %s", code, errOut.String())
	}
	golden, e := os.ReadFile("../../testdata/doctor/command.txt")
	if e != nil || out.String() != string(golden) {
		t.Fatalf("%v\n%s", e, out.String())
	}
}
