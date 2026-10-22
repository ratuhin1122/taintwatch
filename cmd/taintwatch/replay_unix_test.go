//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
)

func TestLiveAuditCanReplayActionChanges(t *testing.T) {
	home := postHome(t)
	var out, errout bytes.Buffer
	if code := run([]string{"hook", "post"}, strings.NewReader(strings.ReplaceAll(postPayload("WebFetch", `{}`), "post-session", "pre-session")), &out, &errout); code != 0 || errout.Len() != 0 {
		t.Fatal(code, errout.String())
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"hook", "pre"}, strings.NewReader(prePayload("Read", `{"file_path":"/project/.env"}`)), &out, &errout); code != 0 || errout.Len() != 0 || !strings.Contains(out.String(), `"permissionDecision":"ask"`) {
		t.Fatal(code, out.String(), errout.String())
	}
	log := filepath.Join(home, "audit.jsonl")
	before, e := os.ReadFile(log)
	if e != nil {
		t.Fatal(e)
	}
	lines := bytes.Split(bytes.TrimSpace(before), []byte("\n"))
	record, e := audit.DecodeRecord(lines[len(lines)-1])
	if e != nil || record.Replay == nil {
		t.Fatal(record, e)
	}
	defaults := policy.Defaults()
	if record.Replay.Fingerprint != rules.MatchFingerprint(defaults) {
		t.Fatal("production policy fingerprint mismatch")
	}
	candidate := filepath.Join(t.TempDir(), "new.yaml")
	if e = os.WriteFile(candidate, []byte("version: 1\nrules:\n  TW001:\n    action: deny\n"), 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	errout.Reset()
	if code := run([]string{"replay", "--log", log, "--policy", candidate}, strings.NewReader(""), &out, &errout); code != 0 || errout.Len() != 0 || !strings.Contains(out.String(), "ask -> deny (TW001 -> TW001)") {
		t.Fatal(code, out.String(), errout.String())
	}
	after, _ := os.ReadFile(log)
	if !bytes.Equal(before, after) {
		t.Fatal("replay modified live log")
	}
}
