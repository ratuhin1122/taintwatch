package eval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func action(id, decision, rule string, e *Expectation) Observation {
	return Observation{Scenario: id, Step: "request", Category: "test-category", Decision: decision, Rule: rule, Reason: "test reason", Expected: e}
}
func TestMetrics(t *testing.T) {
	ask := &Expectation{Decision: "ask"}
	allow := &Expectation{Decision: "allow"}
	deny := &Expectation{Decision: "deny"}
	rule := &Expectation{Decision: "ask", Rule: "TW001"}
	r := Report{Scenarios: []ScenarioResult{
		{ID: "caught", Class: "attacks", Category: "test-category", Actions: []Observation{action("caught", "deny", "TW001", ask)}},
		{ID: "partial", Class: "attacks", Category: "test-category", Actions: []Observation{action("partial", "ask", "TW001", ask), action("partial", "allow", "default.allow", ask)}},
		{ID: "known", Class: "attacks", Category: "test-category", KnownMiss: true, Actions: []Observation{action("known", "allow", "default.allow", ask), action("known", "ask", "TW001", allow)}},
		{ID: "known-rule", Class: "attacks", Category: "test-category", KnownMiss: true, Actions: []Observation{action("known-rule", "ask", "TW002", rule)}},
		{ID: "known-deny", Class: "attacks", Category: "test-category", KnownMiss: true, Actions: []Observation{action("known-deny", "ask", "TW001", deny)}},
		{ID: "benign-one", Class: "benign", Category: "test-category", Actions: []Observation{action("benign-one", "ask", "TW001", allow), action("benign-one", "allow", "default.allow", allow), action("benign-one", "ask", "TW002", nil)}},
		{ID: "benign-two", Class: "benign", Category: "test-category", Actions: []Observation{action("benign-two", "deny", "TW001", allow)}},
	}}
	aggregate(&r)
	if r.Attacks.Total != 2 || r.Attacks.Caught != 1 || r.Attacks.Fraction != 0.5 || !r.Attacks.Defined {
		t.Fatal(r.Attacks)
	}
	if r.KnownMisses.Total != 3 || r.KnownMisses.Caught != 2 {
		t.Fatal(r.KnownMisses)
	}
	if r.Benign.Sessions != 2 || r.Benign.ToolCalls != 4 || r.Benign.Asks != 2 || r.Benign.Denies != 1 || r.Benign.AsksPerSession != 1 || r.Benign.AsksPer100Calls != 50 {
		t.Fatal(r.Benign)
	}
	if r.ExpectedFailures != 1 || r.GateFailures != 9 || len(r.Misses) != 2 || len(r.BenignAsks) != 2 || len(r.BenignDenies) != 1 {
		t.Fatalf("counts gate=%d xfail=%d misses=%d", r.GateFailures, r.ExpectedFailures, len(r.Misses))
	}
	if len(r.Categories) != 1 || !reflect.DeepEqual(r.Categories[0].Benign, r.Benign) || !reflect.DeepEqual(r.Categories[0].Attacks, r.Attacks) {
		t.Fatal(r.Categories)
	}
	if len(r.Rules) != 2 || r.Rules[0].Rule != "TW001" || r.Rules[0].Hits != 6 || r.Rules[1].Rule != "TW002" || r.Rules[1].Hits != 2 {
		t.Fatal(r.Rules)
	}
}

func TestZeroDenominators(t *testing.T) {
	r := Report{}
	aggregate(&r)
	if r.Attacks.Defined || r.Attacks.Fraction != 0 || r.Benign.AsksPerSession != 0 || r.Benign.AsksPer100Calls != 0 {
		t.Fatal(r)
	}
	var b bytes.Buffer
	if err := Render(&b, r, "human"); err != nil || !strings.Contains(b.String(), "n/a") {
		t.Fatal(b.String(), err)
	}
}

func TestKnownMissUnexpectedPassFailsGate(t *testing.T) {
	r := Report{Scenarios: []ScenarioResult{{ID: "fixed-miss", Class: "attacks", KnownMiss: true,
		Actions: []Observation{action("fixed-miss", "ask", "TW001", &Expectation{Decision: "ask"})}}}}
	aggregate(&r)
	if r.GateFailures != 1 || r.Attacks.Total != 0 || r.KnownMisses.Total != 1 {
		t.Fatalf("unexpected pass must gate without entering catch rate: %+v", r)
	}
	var b bytes.Buffer
	if err := Render(&b, r, "human"); err != nil || !strings.Contains(b.String(), "remove known_miss") {
		t.Fatalf("missing removal instruction: %s (%v)", b.String(), err)
	}
}

func TestRender(t *testing.T) {
	r := Report{SchemaVersion: 1, CorpusSHA256: "corpus", PolicySHA256: "policy", Scenarios: []ScenarioResult{{ID: "attack-one", Class: "attacks", Category: "test-category", Actions: []Observation{action("attack-one", "allow", "default.allow", &Expectation{Decision: "ask"})}}, {ID: "benign-one", Class: "benign", Category: "test-category", Actions: []Observation{action("benign-one", "ask", "TW002", &Expectation{Decision: "allow"})}}}}
	aggregate(&r)
	for _, format := range []string{"human", "markdown", "json"} {
		t.Run(format, func(t *testing.T) {
			var a, b bytes.Buffer
			if err := Render(&a, r, format); err != nil {
				t.Fatal(err)
			}
			if err := Render(&b, r, format); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
				t.Fatal("nondeterministic output", err)
			}
			if format == "json" {
				var decoded Report
				if err := json.Unmarshal(a.Bytes(), &decoded); err != nil || !reflect.DeepEqual(decoded, r) {
					t.Fatal(err)
				}
				return
			}
			want, e := os.ReadFile(filepath.Join("..", "..", "testdata", "eval", format+".golden"))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(a.Bytes(), want) {
				t.Fatalf("golden mismatch:\n%s", a.String())
			}
		})
	}
	if got := safe(("bad|\u202e\n" + fakeCredential("Bearer ", "private-secret-value"))); strings.ContainsAny(got, "\u202e\n") || strings.Contains(got, "private-secret-value") || !strings.Contains(got, `\|`) {
		t.Fatal(got)
	}
}
