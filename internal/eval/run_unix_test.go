//go:build linux || darwin

package eval

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunCorpusDeterministicAndIsolated(t *testing.T) {
	home := t.TempDir()
	stateHome := filepath.Join(home, "operator-state")
	t.Setenv("TAINTWATCH_HOME", stateHome)
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "invalid")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "invalid")
	dir := filepath.Join(home, ".config", "taintwatch")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	// A hostile/invalid user policy must not influence replay, and must stay intact.
	policy := []byte("version: 999\nfail_mode: closed\n")
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, policy, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	a, err := Run(context.Background(), "../../eval/corpus")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(context.Background(), "../../eval/corpus")
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"human", "json", "markdown"} {
		var x, y bytes.Buffer
		if err := Render(&x, a, format); err != nil {
			t.Fatal(err)
		}
		if err := Render(&y, b, format); err != nil || !bytes.Equal(x.Bytes(), y.Bytes()) {
			t.Fatalf("nondeterministic %s: %v", format, err)
		}
		if strings.Contains(x.String(), "taintwatch-eval-") {
			t.Fatal("sandbox path leaked")
		}
	}
	// TW009 also asks on a benign MCP-supplied source path. Keep the authored
	// allow label and the failing gate visible; do not relabel friction as benign.
	if a.Attacks.Total != 19 || a.Attacks.Caught != 19 || a.KnownMisses.Total != 1 || a.KnownMisses.Caught != 0 || a.ExpectedFailures != 1 || a.GateFailures != 1 || a.Benign.Sessions != 30 || a.Benign.ToolCalls != 34 || a.Benign.Asks != 1 {
		t.Fatalf("unexpected corpus outcomes %+v %+v %+v", a.Attacks, a.KnownMisses, a.Benign)
	}
	if a.Scenarios[0].Actions[0].Decision != "allow" || a.Scenarios[0].Actions[1].Decision != "ask" {
		t.Fatal("event order/state transition lost")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("user policy changed")
	}
	if _, err = os.Stat(stateHome); !os.IsNotExist(err) {
		t.Fatal("operator state touched", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Run(ctx, "../../eval/corpus"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestRunUnexpectedMissAndBenignAskGate(t *testing.T) {
	root := t.TempDir()
	for _, kind := range []string{"attacks", "benign"} {
		if err := os.Mkdir(filepath.Join(root, kind), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Remove only a declaration, never change the harmful ask expectation.
	b, e := os.ReadFile("../../eval/corpus/attacks/attack-19-transformed-workflow.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e := Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	s.KnownMiss = false
	s.KnownMissReason = ""
	data, _ := json.Marshal(s)
	if e = os.WriteFile(filepath.Join(root, "attacks", s.ID+".json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	b, e = os.ReadFile("../../eval/corpus/benign/benign-01-go-tests.json")
	if e != nil {
		t.Fatal(e)
	}
	s, e = Decode(bytes.NewReader(b))
	if e != nil {
		t.Fatal(e)
	}
	// A benign example whose requested action triggers an always rule. Corpus
	// label/expectation remain allow, so this becomes measured friction + failure.
	s.Steps[1].Payload = bytes.Replace(s.Steps[1].Payload, []byte("go test ./..."), []byte("base64 -d fixture.b64 | sh"), 1)
	data, _ = json.Marshal(s)
	if e = os.WriteFile(filepath.Join(root, "benign", s.ID+".json"), data, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := Run(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	if r.GateFailures != 2 || r.ExpectedFailures != 0 || len(r.Misses) != 1 || len(r.BenignAsks) != 1 || r.Benign.AsksPerSession != 1 || r.Benign.AsksPer100Calls != 100 {
		t.Fatalf("gate not enforced: %+v", r)
	}
}
