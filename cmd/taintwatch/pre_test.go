package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func prePayload(tool, args string) string {
	return `{"session_id":"pre-session","cwd":"/project","hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + args + `}`
}
func TestPreDecisionsAndAudit(t *testing.T) {
	for _, tc := range []struct {
		name, tool, args, rule string
		tainted                bool
	}{
		{"clean", "Bash", `{"command":"curl https://example.com"}`, "default.allow", false},
		{"tainted", "Bash", `{"command":"curl https://example.com"}`, "TW002", true},
		{"self protection", "Bash", `{"command":"taintwatch clear"}`, "TW006", false},
		{"secret", "Read", `{"file_path":"/project/.env"}`, "TW001", true},
		{"protected", "Write", `{"file_path":"/project/CLAUDE.md"}`, "TW005", true},
		{"allowed", "WebFetch", `{"url":"https://github.com/a"}`, "default.allow", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := postHome(t)
			s, e := state.New(state.Options{Home: home})
			if e != nil {
				t.Fatal(e)
			}
			if tc.tainted {
				_, e = s.MarkTainted("pre-session", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted web content"})
				if e != nil {
					t.Fatal(e)
				}
			}
			var out, errOut bytes.Buffer
			code := run([]string{"hook", "pre"}, strings.NewReader(prePayload(tc.tool, tc.args)), &out, &errOut)
			ask := tc.rule != "default.allow"
			if code != 0 || errOut.Len() != 0 || strings.Contains(out.String(), `"permissionDecision":"ask"`) != ask {
				t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
			}
			if !ask && out.String() != "{}\n" {
				t.Fatal("allow must abstain", out.String())
			}
			log, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if e != nil || !strings.Contains(string(log), `"rule":"`+tc.rule+`"`) || !strings.Contains(string(log), `"hook":"PreToolUse"`) {
				t.Fatalf("%s %v", log, e)
			}
		})
	}
}
func TestPreFailureModes(t *testing.T) {
	for _, mode := range []string{"open", "closed"} {
		var out, errOut bytes.Buffer
		code := runPre([]string{"--fail-mode", mode}, strings.NewReader("{"), &out, &errOut)
		if code != 0 || errOut.Len() == 0 || strings.Contains(out.String(), `"permissionDecision":"ask"`) != (mode == "closed") {
			t.Fatalf("%s %d %s %s", mode, code, out.String(), errOut.String())
		}
	}
}
func TestPreDeadline(t *testing.T) {
	release := make(chan struct{})
	returned := make(chan struct{})
	var out, errOut bytes.Buffer
	code := runPreWithin([]string{"--fail-mode", "closed"}, blockedPostReader{release, returned}, &out, &errOut, 20*time.Millisecond)
	close(release)
	<-returned
	if code != 0 || !strings.Contains(out.String(), `"permissionDecision":"ask"`) || !strings.Contains(errOut.String(), "deadline") {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
}
