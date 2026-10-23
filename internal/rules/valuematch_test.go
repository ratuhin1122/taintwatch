package rules

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/valuematch"
)

func TestValueProvenanceRule(t *testing.T) {
	url := "https://raw.githubusercontent.com/taintwatch-eval-fixture/collector/main/next.txt"
	for _, tc := range []struct {
		tool, arg, response string
		want                bool
	}{
		{"WebFetch", url, url, true},
		{"Bash", "printf '%s' '" + base64.StdEncoding.EncodeToString([]byte("X"+url+"tail")) + "'", url, false},
		{"Bash", "env FOO=1 /usr/bin/printf '%s' 'https://hook.example/collector'", "https://hook.example/collector", false},
		{"Bash", "printf '%s' 'hook.example'", "hook.example", false},
		{"Bash", "printf '%s' '&#47;&#116;&#109;&#112;&#47;&#111;&#117;&#116;&#46;&#108;&#111;&#103;'", "/tmp/out.log", false},
		{"Write", "/tmp/out.log", "/tmp/out.log", true},
		{"Read", "/project/collector.txt", "/project/collector.txt", false},
		{"Bash", "cat /project/collector.txt", "/project/collector.txt", false},
		{"Bash", "printf x > /project/collector.txt", "/project/collector.txt", false},
		{"Bash", "go test ./...", "go test ./...", false},
		{"WebFetch", "https://github.com/other", "github.com", false},
		{"WebFetch", "https://github.com/other", "https://github.com", false},
		{"WebFetch", "https://github.com/other", "https://github.com/supplied", false},
		{"Write", "/project/src/report.go", "api plus github.com; paraphrase owner", false},
		{"Bash", "printf '%s%s' 'hook.' 'example'", "hook.example", false},
	} {
		t.Run(tc.tool+tc.arg, func(t *testing.T) {
			in := Input{Policy: DefaultPolicy(), Tool: tc.tool, CWD: "/project", Session: state.Session{Tainted: true, TaintEvents: []state.TaintEvent{{Tool: "WebFetch", Source: state.SourceWeb, ValueMatches: valuematch.Extract(tc.response)}}}}
			switch tc.tool {
			case "Bash":
				in.Command = tc.arg
				in.Shell = shellparse.Parse(tc.arg)
			case "WebFetch":
				in.URL = tc.arg
			default:
				in.FilePath = tc.arg
			}
			got := valueMatch(in)
			if (len(got) > 0) != tc.want {
				t.Fatalf("got %v want %t", got, tc.want)
			}
			if tc.want {
				d := Evaluate(in)
				if d.Action != Ask || !strings.Contains(d.Reason, "This argument came from untrusted content read earlier") {
					t.Fatal(d)
				}
			}
			in.Session.Tainted = false
			if d := Evaluate(in); d.RuleID == "TW009" {
				t.Fatal("clean match")
			}
		})
	}
}

func TestValueRulePolicyAndBoundaries(t *testing.T) {
	p := DefaultPolicy()
	in := Input{Policy: p, Tool: "WebFetch", URL: "https://github.com/supplied/path", Session: state.Session{Tainted: true, TaintEvents: []state.TaintEvent{{Tool: "WebFetch", ValueMatches: valuematch.Extract("https://github.com/supplied/path")}}}}
	for _, action := range []Action{Allow, Ask, Deny} {
		o := in.Policy.Overrides["TW009"]
		o.Action = string(action)
		in.Policy.Overrides["TW009"] = o
		if d := Evaluate(in); d.Action != action || d.RuleID != "TW009" {
			t.Fatal(d)
		}
	}
	o := in.Policy.Overrides["TW009"]
	o.Enabled = false
	in.Policy.Overrides["TW009"] = o
	if d := Evaluate(in); d.Action != Allow || d.RuleID != "default.allow" {
		t.Fatal(d)
	}
	// A match after the action scan prefix, or outside the retained event window,
	// is explicitly out of scope rather than silently expanding resource budgets.
	in.Policy = DefaultPolicy()
	in.URL = strings.Repeat("x", valuematch.MaxTextBytes) + "https://github.com/supplied/path"
	if got := valueMatch(in); len(got) != 0 {
		t.Fatal("scan cap ignored")
	}
	in.URL = "https://github.com/supplied/path"
	in.Session.TaintEvents = append(in.Session.TaintEvents, make([]state.TaintEvent, 128)...)
	if got := valueMatch(in); len(got) != 0 {
		t.Fatal("event window ignored")
	}
}
