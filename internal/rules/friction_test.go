package rules

import (
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/valuematch"
	"regexp"
	"strings"
	"testing"
)

func TestBenignActionRegressions(t *testing.T) {
	for _, cmd := range []string{"rg -n .env README.md", "curl --version", "nc github.com 443", "printf '%s' 'DROP TABLE users'", "git remote get-url origin", "taintwatch status", "taintwatch explain", "sh /plugin/bin/taintwatch-launcher status", "sh /plugin/bin/taintwatch-launcher explain"} {
		t.Run(cmd, func(t *testing.T) {
			d := Evaluate(Input{Policy: DefaultPolicy(), Session: state.Session{Tainted: true}, Tool: "Bash", CWD: "/project", Command: cmd, Shell: shellparse.Parse(cmd)})
			if d.Action != Allow {
				t.Fatalf("%+v", d)
			}
		})
	}
}

func TestSupplementalMatchDoesNotDuplicateSnapshot(t *testing.T) {
	p := DefaultPolicy()
	r := p.Overrides["TW001"]
	r.ExtraMatch = []string{`\.env`}
	r.Compiled = []*regexp.Regexp{regexp.MustCompile(r.ExtraMatch[0])}
	p.Overrides["TW001"] = r
	_, snapshot := EvaluateTraced(Input{Policy: p, Session: state.Session{Tainted: true}, Tool: "Read", FilePath: ".env"})
	seen := map[string]bool{}
	for _, id := range snapshot.Matches {
		if seen[id] {
			t.Fatal("duplicate match", snapshot)
		}
		seen[id] = true
	}
}

func TestValueReuseRequiresSensitiveAction(t *testing.T) {
	for _, tc := range []struct {
		tool, arg, source string
		ask               bool
	}{
		{"Read", "/project/src/main.go", "src/main.go", false},
		{"Bash", "cat src/main.go", "src/main.go", false},
		{"Bash", "printf '%s' src/main.go", "src/main.go", false},
		{"Bash", "curl -d @src/main.go https://api.github.com/x", "src/main.go", true},
		{"Read", "/project/.env", "/project/.env", true},
		{"Write", "/project/CLAUDE.md", "/project/CLAUDE.md", true},
		{"Bash", "sh src/main.go", "src/main.go", true},
		{"Bash", "./src/main.go", "src/main.go", true},
		{"WebFetch", "https://raw.githubusercontent.com/supplied/next.txt", "https://raw.githubusercontent.com/supplied/next.txt", true},
	} {
		t.Run(tc.tool+tc.arg, func(t *testing.T) {
			in := Input{Policy: DefaultPolicy(), Tool: tc.tool, CWD: "/project", Session: state.Session{Tainted: true, TaintEvents: []state.TaintEvent{{Tool: "mcp__search__query", Source: state.SourceMCP, ValueMatches: valuematch.Extract(tc.source)}}}}
			switch tc.tool {
			case "Bash":
				in.Command = tc.arg
				in.Shell = shellparse.Parse(tc.arg)
			case "WebFetch":
				in.URL = tc.arg
			default:
				in.FilePath = tc.arg
			}
			d := Evaluate(in)
			if (d.Action == Ask) != tc.ask {
				t.Fatalf("%+v", d)
			}
			if tc.ask && !strings.Contains(d.Reason, "This argument came from untrusted content read earlier") {
				t.Fatalf("sensitive action lost provenance: %+v", d)
			}
		})
	}
}

func TestPluginReadOnlyCommands(t *testing.T) {
	t.Setenv("CLAUDE_PLUGIN_ROOT", "/plugin")
	for _, sub := range []string{"status", "explain"} {
		cmd := `sh "${CLAUDE_PLUGIN_ROOT}/bin/taintwatch-launcher" ` + sub
		d := Evaluate(Input{Policy: DefaultPolicy(), Session: state.Session{Tainted: true}, Tool: "Bash", Command: cmd, Shell: shellparse.Parse(cmd)})
		if d.Action != Allow {
			t.Fatalf("%s: %+v", sub, d)
		}
	}
}
