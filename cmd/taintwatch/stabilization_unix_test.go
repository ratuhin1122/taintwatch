//go:build linux || darwin

package main

import (
	"bytes"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"strings"
	"testing"
)

func TestUnknownSessionIsNotClean(t *testing.T) {
	operatorHome(t)
	var out, errOut bytes.Buffer
	if code := runInspect("status", []string{"--session", "unknown-session"}, &out, &errOut); code != 0 || !strings.Contains(strings.ToLower(out.String()), "session not found") || strings.Contains(out.String(), "Tainted: no") {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
}

func TestExplainShowsPersistedObservationLoss(t *testing.T) {
	operatorHome(t)
	store, err := state.New(state.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.MarkDegraded("", "post observation lost: deadline"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"status", "explain"} {
		var out, errOut bytes.Buffer
		if code := runInspect(name, nil, &out, &errOut); code != 0 || !strings.Contains(out.String(), "Degraded: yes") || !strings.Contains(out.String(), "deadline") {
			t.Fatalf("%s code=%d out=%s err=%s", name, code, out.String(), errOut.String())
		}
	}
}
