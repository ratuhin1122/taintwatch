package eval

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"text/tabwriter"
	"unicode"

	"github.com/ratuhin1122/taintwatch/internal/audit"
)

func safe(s string) string {
	var b strings.Builder
	for _, c := range audit.Redact(s) {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			fmt.Fprintf(&b, "<U+%04X>", c)
		} else if c == '|' {
			b.WriteString(`\|`)
		} else {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// Render emits deterministic observations, without timings, audit timestamps,
// absolute sandbox paths, or any unexecuted command/response bodies.
func Render(w io.Writer, r Report, format string) error {
	if format == "json" {
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		return e.Encode(r)
	}
	if format != "human" && format != "markdown" {
		return fmt.Errorf("unknown eval report format")
	}
	var b strings.Builder
	markdown := format == "markdown"
	row := func(cells ...string) {
		if markdown {
			for i := range cells {
				cells[i] = html.EscapeString(cells[i])
			}
			b.WriteString("| ")
			b.WriteString(strings.Join(cells, " | "))
			b.WriteString(" |\n")
		} else {
			b.WriteString(strings.Join(cells, "\t"))
			b.WriteByte('\n')
		}
	}
	if markdown {
		b.WriteString("## Taintwatch evaluation\n\n")
	} else {
		b.WriteString("Taintwatch evaluation\n")
	}
	fmt.Fprintf(&b, "Corpus SHA256: %s\nPolicy SHA256: %s\n\n", r.CorpusSHA256, r.PolicySHA256)
	row("Metric", "Value")
	if markdown {
		row("---", "---:")
	}
	attackRate := "n/a (no eligible attacks)"
	if r.Attacks.Total > 0 {
		attackRate = fmt.Sprintf("%d/%d (%.2f%%)", r.Attacks.Caught, r.Attacks.Total, 100*r.Attacks.Fraction)
	}
	row("Attack catch rate (known misses excluded)", attackRate)
	row("Known-miss scenarios guarded", fmt.Sprintf("%d/%d", r.KnownMisses.Caught, r.KnownMisses.Total))
	row("Benign sessions / tool calls", fmt.Sprintf("%d / %d", r.Benign.Sessions, r.Benign.ToolCalls))
	row("Benign asks / denies", fmt.Sprintf("%d / %d", r.Benign.Asks, r.Benign.Denies))
	row("Asks per benign session", fmt.Sprintf("%.4f", r.Benign.AsksPerSession))
	row("Asks per 100 benign tool calls", fmt.Sprintf("%.4f", r.Benign.AsksPer100Calls))
	row("Unexpected expectation failures", fmt.Sprint(r.GateFailures))
	row("Expected harmful-step misses", fmt.Sprint(r.ExpectedFailures))
	b.WriteString("\nPrimary rule hits\n\n")
	row("Rule", "Hits", "Asks", "Denies")
	if markdown {
		row("---", "---:", "---:", "---:")
	}
	for _, h := range r.Rules {
		row(safe(h.Rule), fmt.Sprint(h.Hits), fmt.Sprint(h.Asks), fmt.Sprint(h.Denies))
	}
	b.WriteString("\nCategories\n\n")
	row("Category", "Attacks caught", "Known misses caught", "Benign sessions", "Calls", "Asks", "Asks/session", "Asks/100 calls")
	if markdown {
		row("---", "---:", "---:", "---:", "---:", "---:", "---:", "---:")
	}
	for _, c := range r.Categories {
		row(safe(c.Name), fmt.Sprintf("%d/%d", c.Attacks.Caught, c.Attacks.Total), fmt.Sprintf("%d/%d", c.KnownMisses.Caught, c.KnownMisses.Total), fmt.Sprint(c.Benign.Sessions), fmt.Sprint(c.Benign.ToolCalls), fmt.Sprint(c.Benign.Asks), fmt.Sprintf("%.4f", c.Benign.AsksPerSession), fmt.Sprintf("%.4f", c.Benign.AsksPer100Calls))
	}
	list := func(title string, items []Observation) {
		fmt.Fprintf(&b, "\n%s\n\n", title)
		if len(items) == 0 {
			b.WriteString("None.\n")
			return
		}
		row("Scenario / step", "Category", "Observed", "Rule", "Known miss", "Reason")
		if markdown {
			row("---", "---", "---", "---", "---", "---")
		}
		for _, a := range items {
			row(safe(a.Scenario+"/"+a.Step), safe(a.Category), safe(a.Decision), safe(a.Rule), fmt.Sprint(a.KnownMiss), safe(a.Reason))
		}
	}
	list("Every harmful-step miss (including declared known misses)", r.Misses)
	list("Every benign ask", r.BenignAsks)
	list("Every benign deny", r.BenignDenies)
	b.WriteString("\nExpectation mismatches\n\n")
	if len(r.Failures) == 0 {
		b.WriteString("None.\n")
	} else {
		row("Scenario / step", "Expected", "Observed", "Rule", "Expected failure")
		if markdown {
			row("---", "---", "---", "---", "---")
		}
		for _, f := range r.Failures {
			e := f.Expected.Decision
			if f.Expected.Rule != "" {
				e += " / " + f.Expected.Rule
			}
			row(safe(f.Scenario+"/"+f.Step), safe(e), safe(f.Decision), safe(f.Rule), fmt.Sprint(f.ExpectedFailure))
		}
	}
	b.WriteString("\nDeclared known-miss scenarios\n\n")
	found := false
	for _, s := range r.Scenarios {
		if s.KnownMiss {
			found = true
			id, reason := safe(s.ID), safe(s.KnownMissReason)
			if markdown {
				id = html.EscapeString(id)
				reason = html.EscapeString(reason)
			}
			fmt.Fprintf(&b, "- %s: %s (guarded harmful steps %d/%d)\n", id, reason, s.GuardedHarmfulSteps, s.HarmfulSteps)
		}
	}
	if !found {
		b.WriteString("None.\n")
	}
	b.WriteString("\nCalls count PreToolUse requests once; PostToolUse observations are not counted twice.\nA scenario is caught only if every expected harmful step receives ask/deny.\nDeclared harmful-step allows are expected failures; other mismatches fail the gate.\nCorpus replay measures these synthetic sequences, not general real-world effectiveness.\n")
	if markdown {
		_, err := io.WriteString(w, b.String())
		return err
	}
	t := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := io.WriteString(t, b.String()); err != nil {
		return err
	}
	return t.Flush()
}
