package install

import (
	"fmt"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/taint"
	"io"
	"strings"
	"time"
)

// Check is a diagnostic result, never an automatic repair.
type Check struct{ Level, Name, Detail string }

func RenderDoctor(w io.Writer, checks []Check) bool {
	failed := false
	for _, c := range checks {
		fmt.Fprintf(w, "%s %s: %s\n", c.Level, c.Name, c.Detail)
		failed = failed || c.Level == "FAIL"
	}
	return failed
}

// DryRun exercises source classification and sensitive-action rules in memory;
// it never changes real session state or makes a network request.
func DryRun(c policy.Config) error {
	classifier, e := taint.New(taint.FromPolicy(c))
	if e != nil {
		return e
	}
	m, e := classifier.Classify(taint.Input{Tool: "WebFetch", CWD: "/project"})
	if e != nil {
		return e
	}
	session := state.Session{Tainted: m.Tainted, TaintEvents: []state.TaintEvent{{Tool: "WebFetch", Time: time.Unix(0, 0), Source: state.SourceWeb}}}
	d := rules.Evaluate(rules.Input{Policy: rules.FromPolicy(c), Session: session, Tool: "Read", CWD: "/project", FilePath: "/project/.env"})
	if !m.Tainted || d.Action == rules.Allow || !strings.Contains(d.Reason, "WebFetch") {
		return fmt.Errorf("effective policy does not ask/deny secret reads after WebFetch; review sources and TW001")
	}
	return nil
}
