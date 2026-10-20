package hookio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestResults(t *testing.T) {
	// Documentation-derived examples, not real-session fixtures.
	for _, tc := range []struct {
		name   string
		result Result
		want   string
	}{
		{"abstain", Result{}, `{}`},
		{"escaped reason", Ask("quote \" and newline\n"), `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"quote \" and newline\n"}}`},
		{"empty context", AdditionalContext(""), `{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":""}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code, err := tc.result.Write(&out)
			if err != nil || code != 0 || tc.result.ExitCode() != 0 || out.String() != tc.want+"\n" {
				t.Fatalf("code=%d err=%v output=%q", code, err, out.String())
			}
		})
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestResultWriteFailure(t *testing.T) {
	failure := errors.New("output unavailable")
	for _, tc := range []struct {
		name   string
		writer io.Writer
		want   error
	}{
		{"nil", nil, nil},
		{"error", failingWriter{failure}, failure},
		{"short", shortWriter{}, io.ErrShortWrite},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, err := Ask("reason").Write(tc.writer)
			if code != 1 || err == nil || tc.want != nil && !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "write hook result") {
				t.Fatalf("code=%d err=%v", code, err)
			}
		})
	}
}
