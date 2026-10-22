//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBinaryHookDeadline(t *testing.T) {
	binary := os.Getenv("TAINTWATCH_E2E_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "taintwatch")
		cmd := exec.Command("go", "build", "-o", binary, ".")
		if b, e := cmd.CombinedOutput(); e != nil {
			t.Fatalf("build: %v %s", e, b)
		}
	}
	home := t.TempDir()
	for _, kind := range []string{"pre", "post"} {
		for _, mode := range []string{"open", "closed"} {
			t.Run(kind+mode, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				r, w, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer r.Close()
				defer w.Close()
				cmd := exec.CommandContext(ctx, binary, "hook", kind, "--fail-mode", mode)
				cmd.Stdin = r
				cmd.Env = append(os.Environ(), "HOME="+home, "TAINTWATCH_HOME="+filepath.Join(home, "state"))
				var out, errOut bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &errOut
				start := time.Now()
				e = cmd.Run()
				if e != nil || time.Since(start) > 2500*time.Millisecond || !strings.Contains(errOut.String(), "deadline") {
					t.Fatalf("%v elapsed=%s out=%s err=%s", e, time.Since(start), out.String(), errOut.String())
				}
				if mode == "open" && out.String() != "{}\n" {
					t.Fatal(out.String())
				}
				if mode == "closed" && !strings.Contains(out.String(), map[string]string{"pre": "permissionDecision", "post": "additionalContext"}[kind]) {
					t.Fatal(out.String())
				}
			})
		}
	}
}
