//go:build linux || darwin

package hooks

import (
	"context"
	"errors"
	"fmt"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLostPostObservationPersists(t *testing.T) {
	for _, kind := range []string{"oversized", "malformed"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("TAINTWATCH_HOME", t.TempDir())
			body := `{"session_id":"lost","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com"},"tool_response":"`
			if kind == "oversized" {
				body += strings.Repeat("x", hookio.MaxInputBytes) + `"}`
			} else {
				body += "unterminated"
			}
			post := Post(context.Background(), strings.NewReader(body), "open", "", nil, nil, Runtime{})
			if post.Failure == "" {
				t.Fatal("expected processing failure")
			}
			store, err := state.New(state.Options{})
			if err != nil {
				t.Fatal(err)
			}
			session, err := store.Load("lost")
			if err != nil {
				t.Fatal(err)
			}
			// Check persistence without depending on the new state representation.
			if !strings.Contains(fmt.Sprintf("%+v", session), "input decoding") {
				t.Fatalf("observation loss not persisted: %+v", session)
			}
			pre := Pre(context.Background(), strings.NewReader(`{"session_id":"lost","cwd":"/project","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":".env"}}`), "open", nil, Runtime{})
			decision := pre.Result.Permission()
			if decision != "ask" {
				t.Fatalf("lost observation allowed sensitive action: %s", decision)
			}
		})
	}
}

func TestPostInternalFailureDegrades(t *testing.T) {
	for _, kind := range []string{"store-error", "panic", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("TAINTWATCH_HOME", t.TempDir())
			rt := Runtime{}
			ctx := context.Background()
			if kind == "store-error" {
				rt.Store = func(policy.Config) (*state.Store, error) { return nil, errors.New("internal") }
			}
			if kind == "panic" {
				rt.Store = func(policy.Config) (*state.Store, error) { panic("internal") }
			}
			if kind == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			Post(ctx, strings.NewReader(`{"session_id":"lost","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"WebFetch","tool_input":{"url":"https://example.com"},"tool_response":"reference"}`), "open", "", nil, nil, rt)
			store, err := state.New(state.Options{})
			if err != nil {
				t.Fatal(err)
			}
			s, err := store.Load("lost")
			if err != nil || !s.Degraded {
				t.Fatalf("%+v %v", s, err)
			}
		})
	}
}

func TestLoadedProjectRegexDeadline(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TAINTWATCH_HOME", t.TempDir())
	cwd := t.TempDir()
	dir := filepath.Join(cwd, ".taintwatch")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body := "version: 1\nrules:\n  TW006:\n    extra_match:\n      append: ['" + strings.Repeat("a?", 900) + "z']\n"
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := state.New(state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.MarkTainted("regex", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted web result"}); err != nil {
		t.Fatal(err)
	}
	payload := fmt.Sprintf(`{"session_id":"regex","cwd":%q,"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":%q}}`, cwd, "cat .env #"+strings.Repeat("a", 50000))
	start := time.Now()
	out := Pre(context.Background(), strings.NewReader(payload), "open", nil, Runtime{})
	if out.Result.Permission() != "ask" || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("permission=%s elapsed=%s", out.Result.Permission(), time.Since(start))
	}
}

func TestMCPSourceReadIsBenign(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TAINTWATCH_HOME", t.TempDir())
	post := Post(context.Background(), strings.NewReader(`{"session_id":"source-read","cwd":"/project","hook_event_name":"PostToolUse","tool_name":"mcp__search__query","tool_input":{"query":"status"},"tool_response":{"content":[{"type":"text","text":"The implementation is in src/main.go."}]}}`), "open", "", nil, nil, Runtime{})
	if post.Failure != "" {
		t.Fatal(post.Failure)
	}
	pre := Pre(context.Background(), strings.NewReader(`{"session_id":"source-read","cwd":"/project","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/project/src/main.go"}}`), "open", nil, Runtime{})
	if pre.Result.Permission() != "allow" {
		t.Fatal(pre.Result.Permission())
	}
}

func TestDegradedWritePreservesConfiguredRetention(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TAINTWATCH_HOME", t.TempDir())
	dir := filepath.Join(home, ".config", "taintwatch")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("version: 1\nstate:\n  retention_days: 30\n"), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := state.New(state.Options{Retention: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.MarkTainted("old", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "web source"}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-8 * 24 * time.Hour)
	if err := os.Chtimes(filepath.Join(store.Home(), "sessions", "old.json"), old, old); err != nil {
		t.Fatal(err)
	}
	Post(context.Background(), strings.NewReader(`{"session_id":"new",`), "open", "", nil, nil, Runtime{})
	s, err := store.Load("old")
	if err != nil || !s.Tainted {
		t.Fatalf("error recovery expired retained taint: %+v %v", s, err)
	}
}
