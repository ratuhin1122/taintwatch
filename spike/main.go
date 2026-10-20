// Throwaway format probe; this is not the Taintwatch security boundary.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const maxPayload = 8 << 20

func capture(r io.Reader, dir string) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxPayload+1))
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}
	if len(b) > maxPayload {
		return "", errors.New("payload exceeds 8 MiB")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(b, &payload); err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	if payload == nil {
		return "", errors.New("payload must be an object")
	}
	var event string
	if err := json.Unmarshal(payload["hook_event_name"], &event); err != nil {
		return "", fmt.Errorf("decode event: %w", err)
	}
	if event != "PreToolUse" && event != "PostToolUse" {
		return "", fmt.Errorf("unsupported event %q", event)
	}
	// Only an operator-selected directory is used; no hook string becomes a path.
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create capture directory: %w", err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", fmt.Errorf("inspect capture directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("capture directory must be a real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return "", fmt.Errorf("protect capture directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".payload-*")
	if err != nil {
		return "", fmt.Errorf("create capture: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()
	if err := f.Chmod(0600); err != nil {
		return "", fmt.Errorf("protect capture: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		return "", fmt.Errorf("write capture: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("sync capture: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close capture: %w", err)
	}
	// Unique per invocation; rename publishes complete payloads to concurrent readers.
	final := filepath.Join(dir, filepath.Base(tmp)[1:]+".json")
	if err := os.Rename(tmp, final); err != nil {
		return "", fmt.Errorf("publish capture: %w", err)
	}
	if event == "PreToolUse" {
		return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"Taintwatch format spike: approve this harmless test call to capture its result."}}`, nil
	}
	return `{}`, nil
}

func main() {
	dir := flag.String("log-dir", "", "operator-selected capture directory (default: captures beside executable)")
	flag.Parse()
	if *dir == "" {
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "spike: locate executable:", err)
			return
		}
		*dir = filepath.Join(filepath.Dir(exe), "captures")
	}
	type result struct {
		out string
		err error
	}
	done := make(chan result, 1)
	go func() { out, err := capture(os.Stdin, *dir); done <- result{out, err} }()
	select {
	case res := <-done:
		if res.err != nil {
			fmt.Fprintln(os.Stderr, "spike:", res.err)
			return
		}
		fmt.Println(res.out)
	case <-time.After(3 * time.Second):
		// Fail open, exit 0 without decision JSON. Never wait indefinitely for stdin/disk.
		fmt.Fprintln(os.Stderr, "spike: capture timed out (fail open)")
	}
}
