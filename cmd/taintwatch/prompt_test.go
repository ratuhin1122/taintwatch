package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/hookio"
)

type promptPanicReader struct{}

func (promptPanicReader) Read([]byte) (int, error) { panic("private reader details") }

type promptPanicWriter struct{}

func (promptPanicWriter) Write([]byte) (int, error) { panic("private writer details") }

func TestPromptErrorsNeverBlockOrOutput(t *testing.T) {
	for _, tc := range []struct {
		name  string
		in    io.Reader
		args  []string
		stage string
	}{
		{"invalid", strings.NewReader("{"), nil, "input decoding"},
		{"oversized", strings.NewReader(strings.Repeat("x", hookio.MaxInputBytes+1)), nil, "input decoding"},
		{"wrong event", strings.NewReader(`{"session_id":"s","hook_event_name":"PreToolUse","prompt":"secret"}`), nil, "input decoding"},
		{"panic", promptPanicReader{}, nil, "internal panic"},
		{"bad flags", strings.NewReader(""), []string{"--fail-mode", "closed"}, "arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errout bytes.Buffer
			if code := runPrompt(tc.args, tc.in, &out, &errout); code != 0 || out.Len() != 0 || !strings.Contains(errout.String(), tc.stage) || strings.Contains(errout.String(), "private") {
				t.Fatal(code, out.String(), errout.String())
			}
		})
	}
	if code := runPrompt(nil, promptPanicReader{}, promptPanicWriter{}, promptPanicWriter{}); code != 0 {
		t.Fatal(code)
	}
}

func TestPromptBlockedInputDeadline(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	var out bytes.Buffer
	start := time.Now()
	if code := runPromptWithin(nil, r, &out, io.Discard, 40*time.Millisecond); code != 0 || out.Len() != 0 || time.Since(start) > time.Second {
		t.Fatal(code, out.String(), time.Since(start))
	}
}
