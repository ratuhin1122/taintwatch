//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func TestPostAuditFailureStillRecordsTaint(t *testing.T) {
	home := postHome(t)
	s, err := state.New(state.Options{Home: home})
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "audit.jsonl")); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := runPost(nil, strings.NewReader(postPayload("WebFetch", `{}`)), &out, &errOut)
	if code != 0 || !strings.Contains(out.String(), "untrusted data") || !strings.Contains(errOut.String(), "audit persistence") {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	session, err := s.Load("post-session")
	if err != nil || !session.Tainted {
		t.Fatalf("session=%+v err=%v", session, err)
	}
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != "unchanged" {
		t.Fatal("audit followed symlink")
	}
}
