package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestCapture(t *testing.T) {
	for _, tc := range []struct {
		name, payload string
		wantErr, ask  bool
	}{
		{"pre", `{"hook_event_name":"PreToolUse","session_id":"../../escape","tool_input":{}}`, false, true},
		{"post", `{"hook_event_name":"PostToolUse","tool_response":["arbitrary"]}`, false, false},
		{"invalid", `{`, true, false}, {"null", `null`, true, false},
		{"array", `[]`, true, false}, {"missing", `{}`, true, false},
		{"unknown", `{"hook_event_name":"Unknown"}`, true, false},
		{"oversize", strings.Repeat("x", maxPayload+1), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			out, err := capture(strings.NewReader(tc.payload), dir)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			if tc.wantErr {
				return
			}
			if !json.Valid([]byte(out)) || strings.Contains(out, `"permissionDecision":"ask"`) != tc.ask {
				t.Fatalf("output=%s", out)
			}
			files, err := filepath.Glob(filepath.Join(dir, "*.json"))
			if err != nil || len(files) != 1 {
				t.Fatalf("captures=%v error=%v", files, err)
			}
			b, err := os.ReadFile(files[0])
			if err != nil || string(b) != tc.payload {
				t.Fatalf("payload changed: %v", err)
			}
		})
	}
}

func TestConcurrentCapture(t *testing.T) {
	dir := t.TempDir()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := capture(strings.NewReader(`{"hook_event_name":"PostToolUse"}`), dir); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if len(files) != 20 {
		t.Fatalf("got %d captures", len(files))
	}
}

func FuzzCapture(f *testing.F) {
	f.Add(`{"hook_event_name":"PreToolUse"}`)
	f.Add(`null`)
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, s string) { _, _ = capture(strings.NewReader(s), dir) })
}
