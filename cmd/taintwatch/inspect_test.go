package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func TestInspectCommands(t *testing.T) {
	home := postHome(t)
	s, e := state.New(state.Options{Home: home})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.MarkTainted("inspection", state.TaintEvent{Tool: "WebFetch", Source: state.SourceWeb, Reason: "untrusted web"}); e != nil {
		t.Fatal(e)
	}
	if e = audit.Write(s, audit.Record{Session: "inspection", Hook: "PreToolUse", Tool: "Bash", Decision: "ask", Rule: "TW002", Reason: "Destination example.com is outside the allowlist.", StateKnown: true, Tainted: true, TaintSources: []string{"web"}}); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"explain"}, "Asked for approval: Bash [TW002]"},
		{[]string{"explain", "--session", "inspection", "--last", "1"}, "sources: web"},
		{[]string{"status"}, "Tainted: yes"},
		{[]string{"status", "--session", "inspection"}, "Asks in retained history: 1"},
		{[]string{"explain", "--session", "missing"}, "No retained decisions"},
	} {
		var out, errOut bytes.Buffer
		if code := run(tc.args, strings.NewReader(""), &out, &errOut); code != 0 || errOut.Len() != 0 || !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v: %d %s %s", tc.args, code, out.String(), errOut.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"explain", "--json"}, strings.NewReader(""), &out, &errOut); code != 0 || !json.Valid(out.Bytes()) {
		t.Fatalf("%d %s %s", code, out.String(), errOut.String())
	}
}
func TestInspectInvalidFlags(t *testing.T) {
	for _, args := range [][]string{{"explain", "--last", "0"}, {"explain", "--last", "1001"}, {"explain", "extra"}, {"status", "--json"}} {
		var out, errOut bytes.Buffer
		if code := run(args, strings.NewReader(""), &out, &errOut); code != exitUsage {
			t.Fatalf("%v: %d", args, code)
		}
	}
}
