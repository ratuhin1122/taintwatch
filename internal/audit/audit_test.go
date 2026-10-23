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
		{(fakeCredential("sk-", "secretvalue12345")), (fakeCredential("sk-", "secretvalue12345"))},
		{("mcp__" + fakeCredential("sk-", "secretvalue12345__read")), (fakeCredential("sk-", "secretvalue12345"))},
		{(fakeCredential("ghp_", "secretvalue12345")), (fakeCredential("ghp_", "secretvalue12345"))},
		{(fakeCredential("AKIA", "ABCDEFGHIJKLMNOP")), (fakeCredential("AKIA", "ABCDEFGHIJKLMNOP"))},
		{"password=hunter2", "hunter2"},
		{(fakeCredential("Bearer ", "secretvalue12345")), "secretvalue12345"},
		{("authorization: " + fakeCredential("Bearer ", "secretvalue12345")), "secretvalue12345"},
		{(fakeCredential("api_key=", "secretvalue12345")), "secretvalue12345"},
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
