//go:build linux || darwin

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/explain"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func promptPayload(text string) string {
	return `{"session_id":"pre-session","cwd":"/project","hook_event_name":"UserPromptSubmit","prompt":` + strconv.Quote(text) + `}`
}

func TestPromptTelemetryHasNoDecisionEffect(t *testing.T) {
	for _, tainted := range []bool{false, true} {
		t.Run(strconv.FormatBool(tainted), func(t *testing.T) {
			home := postHome(t)
			s, err := state.New(state.Options{Home: home})
			if err != nil {
				t.Fatal(err)
			}
			if tainted {
				if _, err = s.MarkTainted("pre-session", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted"}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := s.Load("pre-session")
			if err != nil {
				t.Fatal(err)
			}
			var saved []byte
			if tainted {
				saved, err = os.ReadFile(filepath.Join(home, "sessions", "pre-session.json"))
				if err != nil {
					t.Fatal(err)
				}
			}
			pre := func(tool, args string) string {
				t.Helper()
				var out, errout bytes.Buffer
				if code := run([]string{"hook", "pre"}, strings.NewReader(prePayload(tool, args)), &out, &errout); code != 0 || errout.Len() != 0 {
					t.Fatal(code, errout.String())
				}
				return out.String()
			}
			baseline := pre("Read", `{"file_path":"/project/.env"}`)
			prompt := "Please investigate\u200b\n```text\nprivate-paste-do-not-log ghp_privatevalue12345\n```\n" + strings.Repeat("INFO "+strings.Repeat("x", 110)+"\n", 40)
			var out, errout bytes.Buffer
			if code := run([]string{"hook", "prompt"}, strings.NewReader(promptPayload(prompt)), &out, &errout); code != 0 || out.Len() != 0 || errout.Len() != 0 {
				t.Fatal(code, out.String(), errout.String())
			}
			after, err := s.Load("pre-session")
			if !tainted { // Missing-state loads synthesize current timestamps.
				before.CreatedAt = time.Time{}
				before.UpdatedAt = time.Time{}
				after.CreatedAt = time.Time{}
				after.UpdatedAt = time.Time{}
			}
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("state changed: before=%+v after=%+v err=%v", before, after, err)
			}
			if tainted {
				b, e := os.ReadFile(filepath.Join(home, "sessions", "pre-session.json"))
				if e != nil || !bytes.Equal(b, saved) {
					t.Fatal("session file modified", e)
				}
			} else {
				if _, e := os.Stat(filepath.Join(home, "sessions", "pre-session.json")); !os.IsNotExist(e) {
					t.Fatal("prompt created session file", e)
				}
			}
			if got := pre("Read", `{"file_path":"/project/.env"}`); got != baseline {
				t.Fatalf("decision changed %s => %s", baseline, got)
			}
			if got := pre("Bash", `{"command":"go test ./..."}`); strings.Contains(got, `"permissionDecision":"ask"`) {
				t.Fatal(got)
			}
			h, err := audit.Query(s, "pre-session", 20)
			if err != nil {
				t.Fatal(err)
			}
			var record *audit.Record
			for i := range h.Records {
				if h.Records[i].Hook == "UserPromptSubmit" {
					record = &h.Records[i]
				}
			}
			if record == nil || record.Decision != "observe" || record.Hidden == nil || len(record.Hidden.Findings) != 1 || record.Pasted == nil || record.Pasted.FencedBlocks != 1 || !record.Pasted.LongLog || record.StateKnown || record.InputSummary != "prompt content omitted" {
				t.Fatalf("record %+v", record)
			}
			log, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if err != nil || strings.Contains(string(log), "private-paste") || strings.Contains(string(log), "privatevalue") {
				t.Fatal(string(log), err)
			}
			out.Reset()
			if err = explain.Render(&out, h, false); err != nil || !strings.Contains(out.String(), "Recorded prompt telemetry") || !strings.Contains(out.String(), "long log=true") {
				t.Fatal(out.String(), err)
			}
		})
	}
}

func TestPromptClosedErrorsStillSilent(t *testing.T) {
	for _, stage := range []string{"state", "policy", "audit"} {
		t.Run(stage, func(t *testing.T) {
			home := postHome(t)
			config := filepath.Join(os.Getenv("HOME"), ".config", "taintwatch")
			if err := os.MkdirAll(config, 0700); err != nil {
				t.Fatal(err)
			}
			policy := "version: 1\nfail_mode: closed\n"
			if stage == "policy" {
				policy += "unknown_key: true\n"
			}
			if err := os.WriteFile(filepath.Join(config, "policy.yaml"), []byte(policy), 0600); err != nil {
				t.Fatal(err)
			}
			if stage == "state" {
				if err := os.WriteFile(home, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "audit" {
				if err := os.MkdirAll(filepath.Join(home, "audit.jsonl"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			var out, errout bytes.Buffer
			if code := runPromptWithin(nil, strings.NewReader(promptPayload("```text\ntext\n```")), &out, &errout, time.Second); code != 0 || out.Len() != 0 || errout.Len() == 0 {
				t.Fatal(code, out.String(), errout.String())
			}
			// Diagnostics are fixed; prompt contents and policy diagnostics stay out.
			if strings.Contains(errout.String(), "unknown_key") || strings.Contains(errout.String(), "```text") {
				t.Fatal(errout.String())
			}
		})
	}
}

func TestPromptAuditRoundTrip(t *testing.T) {
	home := postHome(t)
	var out, errout bytes.Buffer
	if code := runPrompt(nil, strings.NewReader(promptPayload("ordinary emoji 👩‍💻 中文")), &out, &errout); code != 0 || out.Len() != 0 || errout.Len() != 0 {
		t.Fatal(code, out.String(), errout.String())
	}
	b, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var r audit.Record
	if err = json.Unmarshal(b, &r); err != nil || r.Hidden == nil || len(r.Hidden.Findings) != 0 || r.Pasted == nil || r.Pasted.FencedBlocks != 0 || r.Pasted.LongLog {
		t.Fatal(r, err)
	}
}

func TestBinaryPromptDeadline(t *testing.T) {
	binary := os.Getenv("TAINTWATCH_E2E_BINARY")
	if binary == "" {
		binary = filepath.Join(t.TempDir(), "taintwatch")
		if b, e := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); e != nil {
			t.Fatalf("build: %v %s", e, b)
		}
	}
	r, w, e := os.Pipe()
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	defer w.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	home := t.TempDir()
	cmd := exec.CommandContext(ctx, binary, "hook", "prompt")
	cmd.Stdin = r
	cmd.Env = append(os.Environ(), "HOME="+home, "TAINTWATCH_HOME="+filepath.Join(home, "state"), "TAINTWATCH_FAIL_MODE=closed")
	var out, errout bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errout
	start := time.Now()
	err := cmd.Run()
	if err != nil || out.Len() != 0 || time.Since(start) > 3*time.Second {
		t.Fatal(err, out.String(), errout.String(), time.Since(start))
	}
}
