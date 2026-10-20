package hookio

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "hookio", "inputs", name+".documented.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDocumentedInputFixtures(t *testing.T) {
	pre, err := DecodePreToolUse(bytes.NewReader(fixture(t, "pretooluse")))
	if err != nil {
		t.Fatal(err)
	}
	if pre.SessionID != "documented-session" || pre.CWD != "/workspace/demo" || pre.TranscriptPath != "/home/example/.claude/projects/demo/session.jsonl" || pre.PermissionMode != "default" || pre.ToolName != "Bash" || pre.ToolUseID != "documented-tool-call" || string(pre.ToolInput) != `{"command": "printf public-probe"}` {
		t.Fatalf("unexpected PreToolUse: %+v", pre)
	}
	post, err := DecodePostToolUse(bytes.NewReader(fixture(t, "posttooluse")))
	if err != nil {
		t.Fatal(err)
	}
	if post.ToolName != "Bash" || post.SessionID != pre.SessionID || post.ToolUseID != pre.ToolUseID || post.DurationMS == nil || *post.DurationMS != 12 || string(post.ToolResponse) != `{"stdout": "public-probe", "stderr": "", "interrupted": false, "isImage": false}` {
		t.Fatalf("unexpected PostToolUse: %+v", post)
	}
	prompt, err := DecodeUserPromptSubmit(bytes.NewReader(fixture(t, "prompt")))
	if err != nil || prompt.Prompt != "Summarize the public test file." || prompt.SessionID != pre.SessionID {
		t.Fatalf("prompt=%+v err=%v", prompt, err)
	}
	start, err := DecodeSessionStart(bytes.NewReader(fixture(t, "session-start")))
	if err != nil || start.Source != "startup" || start.Model != "" || start.SessionTitle != "" || start.SessionID != pre.SessionID {
		t.Fatalf("start=%+v err=%v", start, err)
	}
}

func TestTolerantDecoding(t *testing.T) {
	pre, err := DecodePreToolUse(strings.NewReader(`{"session_id":"../../untrusted-id","hook_event_name":"PreToolUse","tool_name":"mcp__example__read","tool_input":{},"extra":{"new":true},"mcp_server":{"name":"example","source":"future-source","new":7},"effort":{"level":"future-level"},"prompt_id":"p","scratchpad_dir":"/tmp/s","agent_id":"a","agent_type":"Explore"}`))
	if err != nil {
		t.Fatal(err)
	}
	if pre.SessionID != "../../untrusted-id" || pre.ToolUseID != "" || pre.MCPServer == nil || pre.MCPServer.Source != "future-source" || pre.Effort == nil || pre.Effort.Level != "future-level" || pre.PromptID != "p" || pre.AgentID != "a" || pre.AgentType != "Explore" || pre.ScratchpadDir != "/tmp/s" {
		t.Fatalf("decoded=%+v", pre)
	}
	for _, value := range []string{`null`, `"text"`, `[1,{"future":true}]`, `{"any":{"shape":true}}`, `123`, `true`} {
		t.Run(value, func(t *testing.T) {
			// Synthetic shape probes, not claims about actual tool result schemas.
			b := `{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Read","tool_input":{},"tool_response":` + value + `,"future":true}`
			post, err := DecodePostToolUse(strings.NewReader(b))
			if err != nil || string(post.ToolResponse) != value || post.DurationMS != nil || post.MCPServer != nil {
				t.Fatalf("post=%+v err=%v", post, err)
			}
		})
	}
	prompt, err := DecodeUserPromptSubmit(strings.NewReader(`{"session_id":"s","hook_event_name":"UserPromptSubmit","prompt":"","future":true}`))
	if err != nil || prompt.Prompt != "" {
		t.Fatalf("prompt=%+v err=%v", prompt, err)
	}
	start, err := DecodeSessionStart(strings.NewReader(`{"session_id":"s","hook_event_name":"SessionStart","source":"future-source","model":"example-model","session_title":"Public test","agent_type":"custom"}`))
	if err != nil || start.Source != "future-source" || start.Model != "example-model" || start.SessionTitle != "Public test" || start.AgentType != "custom" {
		t.Fatalf("start=%+v err=%v", start, err)
	}
}

func TestDecoderErrors(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		want          error
	}{
		{"empty", "", ErrInvalidInput},
		{"null", "null", ErrInvalidInput},
		{"array", "[]", ErrInvalidInput},
		{"broken", `{`, ErrInvalidInput},
		{"non-JSON whitespace", "\u00a0" + `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}`, ErrInvalidInput},
		{"trailing object", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}} {}`, ErrInvalidInput},
		{"wrong event", `{"session_id":"s","hook_event_name":"SessionStart"}`, ErrUnexpectedEvent},
		{"missing session", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}`, ErrInvalidInput},
		{"missing tool", `{"session_id":"s","hook_event_name":"PreToolUse","tool_input":{}}`, ErrInvalidInput},
		{"missing input", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read"}`, ErrInvalidInput},
		{"null input", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":null}`, ErrInvalidInput},
		{"array input", `{"session_id":"s","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":[]}`, ErrInvalidInput},
		{"typed mismatch", `{"session_id":123}`, ErrInvalidInput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, err := DecodePreToolUse(strings.NewReader(tc.payload))
			if !errors.Is(err, tc.want) || input.SessionID != "" || input.ToolInput != nil {
				t.Fatalf("input=%+v err=%v want=%v", input, err, tc.want)
			}
		})
	}
	_, err := DecodePostToolUse(strings.NewReader(`{"session_id":"s","hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{}}`))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing result: %v", err)
	}
	_, err = DecodePreToolUse(nil)
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil reader: %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type endlessReader struct{ read int }

func (r *endlessReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = ' '
	}
	r.read += len(b)
	return len(b), nil
}

func TestDecoderBoundaries(t *testing.T) {
	base := `{"session_id":"s","hook_event_name":"SessionStart","source":"startup"}`
	atLimit := base + strings.Repeat(" ", MaxInputBytes-len(base))
	if _, err := DecodeSessionStart(strings.NewReader(atLimit)); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	if _, err := DecodeSessionStart(strings.NewReader(atLimit + " ")); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("over limit: %v", err)
	}
	endless := &endlessReader{}
	if _, err := DecodeSessionStart(endless); !errors.Is(err, ErrInputTooLarge) || endless.read != MaxInputBytes+1 {
		t.Fatalf("err=%v read=%d", err, endless.read)
	}
	failure := errors.New("reader failed")
	if _, err := DecodeSessionStart(errorReader{failure}); !errors.Is(err, failure) {
		t.Fatalf("read error: %v", err)
	}
	for _, decode := range []func(io.Reader) error{
		func(r io.Reader) error { _, err := DecodePreToolUse(r); return err },
		func(r io.Reader) error { _, err := DecodePostToolUse(r); return err },
		func(r io.Reader) error { _, err := DecodeUserPromptSubmit(r); return err },
	} {
		if err := decode(strings.NewReader(atLimit + " ")); !errors.Is(err, ErrInputTooLarge) {
			t.Fatalf("shared cap: %v", err)
		}
	}
}

func FuzzDecoder(f *testing.F) {
	for _, name := range []string{"pretooluse", "posttooluse", "prompt", "session-start"} {
		f.Add(fixture(f, name))
	}
	for _, seed := range []string{"null", "[]", "{}", "{", `{"session_id":42}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		// Every decoder must tolerate adversarial input without panicking.
		pre, preErr := DecodePreToolUse(bytes.NewReader(b))
		post, postErr := DecodePostToolUse(bytes.NewReader(b))
		prompt, promptErr := DecodeUserPromptSubmit(bytes.NewReader(b))
		start, startErr := DecodeSessionStart(bytes.NewReader(b))
		if preErr == nil && (pre.SessionID == "" || pre.HookEventName != "PreToolUse" || !json.Valid(pre.ToolInput)) {
			t.Fatal("accepted an invalid pre-tool envelope")
		}
		if postErr == nil && (post.SessionID == "" || post.HookEventName != "PostToolUse" || !json.Valid(post.ToolResponse)) {
			t.Fatal("accepted an invalid post-tool envelope")
		}
		if promptErr == nil && (prompt.SessionID == "" || prompt.HookEventName != "UserPromptSubmit") {
			t.Fatal("accepted an invalid prompt envelope")
		}
		if startErr == nil && (start.SessionID == "" || start.HookEventName != "SessionStart") {
			t.Fatal("accepted an invalid session envelope")
		}
		if (preErr == nil || postErr == nil || promptErr == nil || startErr == nil) && (len(b) > MaxInputBytes || !json.Valid(b)) {
			t.Fatal("accepted oversized or invalid JSON")
		}
	})
}
