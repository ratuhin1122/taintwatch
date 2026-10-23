//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/taint"
)

func TestHiddenPostTelemetry(t *testing.T) {
	for _, tc := range []struct {
		tool string
		scan bool
	}{{"WebFetch", true}, {"WebSearch", true}, {"mcp__public__read", true}, {"Write", false}} {
		t.Run(tc.tool, func(t *testing.T) {
			home := postHome(t)
			payload := func(body string) string {
				return `{"session_id":"pre-session","cwd":"/project","hook_event_name":"PostToolUse","tool_name":` + strconv.Quote(tc.tool) + `,"tool_input":{},"tool_response":{"content":[{"text":` + strconv.Quote(body) + `}]}}`
			}
			call := func(body string) string {
				t.Helper()
				var out, errout bytes.Buffer
				if code := run([]string{"hook", "post"}, strings.NewReader(payload(body)), &out, &errout); code != 0 || errout.Len() != 0 {
					t.Fatal(code, errout.String())
				}
				return out.String()
			}
			baseline := call("ordinary response")
			if got := call(("text\u200b <!-- " + fakeCredential("ghp_", "privatecontent12345") + " -->")); got != baseline {
				t.Fatalf("content changed hook output: %s vs %s", got, baseline)
			}
			b, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(b), "privatecontent") {
				t.Fatalf("leak %s", b)
			}
			lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
			var r audit.Record
			if e = json.Unmarshal(lines[len(lines)-1], &r); e != nil {
				t.Fatal(e)
			}
			if r.Decision != "allow" || (r.Hidden != nil) != tc.scan {
				t.Fatalf("record %+v", r)
			}
			if tc.scan && (len(r.Hidden.Findings) != 2 || r.Hidden.Findings[0].Count != 1) {
				t.Fatalf("hidden %+v", r.Hidden)
			}
			// PreToolUse still allows a harmless action after either response.
			var out, errout bytes.Buffer
			code := run([]string{"hook", "pre"}, strings.NewReader(prePayload("Bash", `{"command":"go test ./..."}`)), &out, &errout)
			if code != 0 || errout.Len() != 0 || strings.Contains(out.String(), `"permissionDecision":"ask"`) {
				t.Fatal(code, out.String(), errout.String())
			}
			out.Reset()
			errout.Reset()
			if code = run([]string{"explain", "--session", "pre-session"}, strings.NewReader(""), &out, &errout); code != 0 || errout.Len() != 0 {
				t.Fatal(code, errout.String())
			}
			if strings.Contains(out.String(), "Content hint (informational):") != tc.scan {
				t.Fatal(out.String())
			}
		})
	}
}

func TestHiddenPostScanCap(t *testing.T) {
	home := postHome(t)
	payload := `{"session_id":"s","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"WebFetch","tool_input":{},"tool_response":` + strconv.Quote(strings.Repeat("a", hidden.MaxBytes)+"\u200b") + `}`
	var out, errout bytes.Buffer
	// Exercise the prefix boundary independently of timing instrumentation from
	// -race. Production timeout behavior has separate guarded-hook tests.
	if code := runPostWithin(nil, strings.NewReader(payload), &out, &errout, 20*time.Second); code != 0 || errout.Len() != 0 {
		t.Fatal(code, errout.String())
	}
	b, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	var r audit.Record
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	if r.Hidden == nil || !r.Hidden.Truncated || r.Hidden.BytesScanned != hidden.MaxBytes || len(r.Hidden.Findings) != 0 {
		t.Fatalf("report %+v", r.Hidden)
	}
}

func TestHiddenTrustedResponseInTaintedSession(t *testing.T) {
	home := postHome(t)
	p := taint.DefaultPolicy()
	p.TrustedServers = []string{"trusted"}
	c, err := taint.New(p)
	if err != nil {
		t.Fatal(err)
	}
	if o := processPost(strings.NewReader(postPayload("WebFetch", `{}`)), c, "open"); o.failure != "" {
		t.Fatal(o.failure)
	}
	payload := `{"session_id":"post-session","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"mcp__trusted__read","tool_input":{},"tool_response":"text\u200b"}`
	if o := processPost(strings.NewReader(payload), c, "open"); o.failure != "" {
		t.Fatal(o.failure)
	}
	s, err := state.New(state.Options{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	session, err := s.Load("post-session")
	if err != nil || !session.Tainted || len(session.TaintEvents) != 1 {
		t.Fatal(session, err)
	}
	b, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	var r audit.Record
	if err = json.Unmarshal(lines[len(lines)-1], &r); err != nil {
		t.Fatal(err)
	}
	if r.Hidden != nil || !r.Tainted || r.Decision != "allow" {
		t.Fatalf("trusted response was scanned: %+v", r)
	}
}
