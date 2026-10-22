package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           []string
		code           int
		stdout, stderr string
	}{
		{"missing", nil, exitUsage, "", "Usage:"},
		{"unknown", []string{"wat"}, exitUsage, "", "unknown subcommand"},
		{"version", []string{"version"}, exitOK, version + "\n", ""},
		{"extra", []string{"version", "extra"}, exitUsage, "", "takes no arguments"},
		{"bad flag", []string{"version", "--unknown"}, exitUsage, "", "flag provided but not defined"},
		{"no hook", []string{"hook"}, exitUsage, "", "requires"},
		{"bad hook", []string{"hook", "unknown"}, exitUsage, "", "unknown hook"},
		{"extra hook argument", []string{"hook", "prompt", "unexpected"}, exitUsage, "", "take no arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if code := run(tc.args, strings.NewReader(""), &out, &errOut); code != tc.code {
				t.Fatalf("exit=%d, want %d", code, tc.code)
			}
			if out.String() != tc.stdout || !strings.Contains(errOut.String(), tc.stderr) {
				t.Fatalf("stdout=%q stderr=%q", out.String(), errOut.String())
			}
		})
	}
}

func TestHelpAndStubs(t *testing.T) {
	commands := [][]string{{}, {"version"}, {"explain"}, {"status"}, {"policy"}, {"policy", "check"}, {"policy", "show"}, {"hook"}, {"hook", "pre"}, {"hook", "post"}, {"hook", "prompt"}, {"hook", "session-start"}}
	for _, command := range commands {
		for _, help := range []string{"--help", "-h"} {
			args := append(append([]string{}, command...), help)
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				var out, errOut bytes.Buffer
				if code := run(args, strings.NewReader(""), &out, &errOut); code != exitOK || !strings.Contains(out.String(), "Usage:") || errOut.Len() != 0 {
					t.Fatalf("exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
				}
			})
		}
		if len(command) == 0 || command[0] == "version" || command[0] == "policy" || command[0] == "explain" || command[0] == "status" || len(command) == 1 && command[0] == "hook" || len(command) == 2 && command[0] == "hook" && (command[1] == "post" || command[1] == "pre") {
			continue
		}
		var out, errOut bytes.Buffer
		if code := run(command, strings.NewReader(""), &out, &errOut); code != exitFailure || out.Len() != 0 || !strings.Contains(errOut.String(), "not implemented") {
			t.Fatalf("%v: exit=%d stdout=%q stderr=%q", command, code, out.String(), errOut.String())
		}
	}
}

func FuzzDispatcher(f *testing.F) {
	f.Add("hook", "pre")
	f.Add("version", "--help")
	f.Fuzz(func(t *testing.T, command, arg string) {
		switch command {
		case "allow", "disallow", "clear", "install", "uninstall":
			return
		} // Never mutate operator files during fuzzing.
		var out, errOut bytes.Buffer
		code := run([]string{command, arg}, strings.NewReader(""), &out, &errOut)
		if code < exitOK || code > exitUsage {
			t.Fatalf("unexpected exit %d", code)
		}
	})
}
