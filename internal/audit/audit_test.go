package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type memorySink struct {
	data []byte
	err  error
}

func (s *memorySink) AppendAudit(b []byte) error { s.data = append([]byte(nil), b...); return s.err }

func TestRedaction(t *testing.T) {
	for _, tc := range []struct{ input, secret string }{
		{"sk-secretvalue12345", "sk-secretvalue12345"},
		{"mcp__sk-secretvalue12345__read", "sk-secretvalue12345"},
		{"ghp_secretvalue12345", "ghp_secretvalue12345"},
		{"AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP"},
		{"password=hunter2", "hunter2"},
		{"Bearer secretvalue12345", "secretvalue12345"},
		{"authorization: Bearer secretvalue12345", "secretvalue12345"},
		{"api_key=secretvalue12345", "secretvalue12345"},
		{`password="two word secret"`, "two word secret"},
		{`password='two word secret'`, "two word secret"},
	} {
		sink := &memorySink{}
		if err := Write(sink, Record{Session: "session", Hook: "PostToolUse", Tool: tc.input, Reason: tc.input, InputSummary: tc.input, TaintSources: []string{tc.input}}); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(sink.data), tc.secret) || !json.Valid(sink.data) {
			t.Fatalf("secret leaked or invalid record: %s", sink.data)
		}
		var record Record
		if err := json.Unmarshal(sink.data, &record); err != nil {
			t.Fatal(err)
		}
		if record.TS.IsZero() || record.InputSummary != "tool arguments and response omitted" {
			t.Fatal("invalid record defaults")
		}
	}
	errExpected := errors.New("disk unavailable")
	if err := Write(&memorySink{err: errExpected}, Record{}); !errors.Is(err, errExpected) {
		t.Fatalf("error not wrapped: %v", err)
	}
}
