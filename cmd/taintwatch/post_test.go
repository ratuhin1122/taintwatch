package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/taint"
)

func postPayload(tool, args string) string {
	// Synthetic documented-envelope probes, never claimed to be live captures.
	return `{"session_id":"post-session","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"` + tool + `","tool_input":` + args + (",\"tool_response\":{\"public\":\"opaque\",\"secret\":\"" + fakeCredential("sk-", "secretvalue12345") + "\"}}")
}

func postHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("secure state requires Unix")
	}
	home := filepath.Join(t.TempDir(), "state")
	t.Setenv("TAINTWATCH_HOME", home)
	userHome := filepath.Join(t.TempDir(), "user-home")
	t.Setenv("HOME", userHome)
	t.Setenv("USERPROFILE", userHome)
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "")
	return home
}

func TestPostPersistenceAndContext(t *testing.T) {
	for _, tc := range []struct {
		name, tool, args string
		flags            []string
		tainted          bool
	}{
		{"web", "WebFetch", ("{\"url\":\"https://example.com/?" + fakeCredential("token=", "secretvalue") + "\"}"), nil, true},
		{"search", "WebSearch", `{"query":"public search"}`, nil, true},
		{"mcp", "mcp__public__read", `{}`, nil, true},
		{"reader", "Bash", `{"command":"curl https://example.com"}`, nil, true},
		{"ordinary shell", "Bash", `{"command":"go test ./..."}`, nil, false},
		{"other", "Write", `{}`, nil, false},
		{"paranoid", "Read", `{"file_path":"/project/main.go"}`, []string{"--profile", "paranoid"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := postHome(t)
			var out, errOut bytes.Buffer
			args := append([]string{"hook", "post"}, tc.flags...)
			code := run(args, strings.NewReader(postPayload(tc.tool, tc.args)), &out, &errOut)
			if code != 0 || errOut.Len() != 0 {
				t.Fatalf("code=%d stderr=%s", code, errOut.String())
			}
			if strings.Contains(out.String(), "untrusted data") != tc.tainted || strings.Contains(out.String(), "permissionDecision") {
				t.Fatalf("unexpected post output: %s", out.String())
			}
			s, err := state.New(state.Options{Home: home})
			if err != nil {
				t.Fatal(err)
			}
			session, err := s.Load("post-session")
			if err != nil || session.Tainted != tc.tainted {
				t.Fatalf("session=%+v err=%v", session, err)
			}
			log, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(log), "\n") != 1 || !strings.Contains(string(log), `"hook":"PostToolUse"`) || !strings.Contains(string(log), `"state_known":true`) || strings.Contains(string(log), "secretvalue") || strings.Contains(out.String(), "secretvalue") {
				t.Fatalf("bad/redaction-failed audit: %s output=%s", log, out.String())
			}
		})
	}
}

func TestPostCleanSourcePreservesTaint(t *testing.T) {
	home := postHome(t)
	c, _ := taint.New(taint.DefaultPolicy())
	first := processPost(strings.NewReader(postPayload("WebFetch", `{}`)), c, "open")
	if first.failure != "" {
		t.Fatal(first.failure)
	}
	second := processPost(strings.NewReader(postPayload("Write", `{}`)), c, "open")
	if second.failure != "" {
		t.Fatal(second.failure)
	}
	s, _ := state.New(state.Options{Home: home})
	session, err := s.Load("post-session")
	if err != nil || !session.Tainted || len(session.TaintEvents) != 1 {
		t.Fatalf("taint was cleared: %+v %v", session, err)
	}
	log, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if err != nil || strings.Count(string(log), `"tainted":true`) != 2 {
		t.Fatalf("audit=%s err=%v", log, err)
	}
}

func TestPostErrorsNeverBlock(t *testing.T) {
	operatorHome(t)
	for _, tc := range []struct {
		name, input string
		args        []string
		closed      bool
	}{
		{"bad JSON", "{", nil, false},
		{"closed bad JSON", "{", []string{"--fail-mode", "closed"}, true},
		{"wrong event", `{"session_id":"s","hook_event_name":"PreToolUse"}`, nil, false},
		{"oversized", strings.Repeat("x", 8<<20+1), nil, false},
		{"bad flags", "", []string{"--unknown"}, false},
		{"bad profile", "", []string{"--profile", "invalid"}, false},
		{"bad fail mode", "", []string{"--fail-mode", "invalid"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runPost(tc.args, strings.NewReader(tc.input), &out, &errOut)
			if code != 0 || errOut.Len() == 0 || strings.Contains(out.String(), "permissionDecision") || strings.Contains(out.String(), `"decision":"block"`) || strings.Contains(out.String(), "obtain the user's confirmation") != tc.closed {
				t.Fatalf("code=%d out=%s stderr=%s", code, out.String(), errOut.String())
			}
		})
	}
	for _, mode := range []string{"open", "closed"} {
		t.Run("state unavailable "+mode, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "not-a-directory")
			if err := os.WriteFile(home, []byte("keep"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TAINTWATCH_HOME", home)
			var out, errOut bytes.Buffer
			code := runPost([]string{"--fail-mode", mode}, strings.NewReader(postPayload("WebFetch", `{}`)), &out, &errOut)
			if code != 0 || errOut.Len() == 0 || strings.Contains(out.String(), "secretvalue") || strings.Contains(errOut.String(), "secretvalue") {
				t.Fatalf("code=%d out=%s stderr=%s", code, out.String(), errOut.String())
			}
		})
	}
}

type blockedPostReader struct {
	release  <-chan struct{}
	returned chan<- struct{}
}

func (r blockedPostReader) Read([]byte) (int, error) {
	<-r.release
	close(r.returned)
	return 0, io.EOF
}

type postErrorWriter struct{}

func (postErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestPostDeadlineAndOutputFailure(t *testing.T) {
	release := make(chan struct{})
	returned := make(chan struct{})
	var out, errOut bytes.Buffer
	start := time.Now()
	code := runPostWithin(nil, blockedPostReader{release, returned}, &out, &errOut, 250*time.Millisecond)
	close(release)
	// Cancellation may prevent Read from being called; it need not signal returned.
	if code != 0 || time.Since(start) > 2*time.Second || !strings.Contains(errOut.String(), "deadline") {
		t.Fatalf("code=%d elapsed=%v stderr=%s", code, time.Since(start), errOut.String())
	}
	errOut.Reset()
	code = runPost(nil, strings.NewReader("{"), postErrorWriter{}, &errOut)
	if code != 0 || !strings.Contains(errOut.String(), "could not write hook output") {
		t.Fatalf("code=%d stderr=%s", code, errOut.String())
	}
}

func TestPostErrorAudit(t *testing.T) {
	home := postHome(t)
	var out, errOut bytes.Buffer
	code := runPost([]string{"--fail-mode", "closed"}, strings.NewReader(postPayload("Bash", `{"command":42}`)), &out, &errOut)
	log, err := os.ReadFile(filepath.Join(home, "audit.jsonl"))
	if code != 0 || err != nil || !strings.Contains(string(log), `"rule":"post.error"`) || !strings.Contains(string(log), `"state_known":false`) || strings.Contains(string(log), "secretvalue") {
		t.Fatalf("code=%d err=%v log=%s", code, err, log)
	}
}
