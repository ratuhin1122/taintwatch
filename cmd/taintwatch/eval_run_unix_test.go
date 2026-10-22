//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corpus "github.com/ratuhin1122/taintwatch/internal/eval"
)

func TestEvalRunCLI(t *testing.T) {
	for _, format := range []string{"--json", "--markdown"} {
		var out, errout bytes.Buffer
		if code := runEval([]string{"run", format, "../../eval/corpus"}, &out, &errout); code != 0 || errout.Len() != 0 {
			t.Fatal(code, out.String(), errout.String())
		}
		if format == "--json" {
			var r corpus.Report
			if e := json.Unmarshal(out.Bytes(), &r); e != nil || r.GateFailures != 0 || r.ExpectedFailures != 3 || r.Attacks.Caught != 17 {
				t.Fatal(e, r.GateFailures, r.ExpectedFailures)
			}
		} else if !strings.Contains(out.String(), "17/17") {
			t.Fatal(out.String())
		}
	}
	root := t.TempDir()
	for _, kind := range []string{"attacks", "benign"} {
		if e := os.Mkdir(filepath.Join(root, kind), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"attacks/attack-20-allowlisted-egress.json", "benign/benign-01-go-tests.json"} {
		b, e := os.ReadFile(filepath.Join("..", "..", "eval", "corpus", name))
		if e != nil {
			t.Fatal(e)
		}
		s, e := corpus.Decode(bytes.NewReader(b))
		if e != nil {
			t.Fatal(e)
		}
		s.KnownMiss = false
		s.KnownMissReason = ""
		b, e = json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(root, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	var out, errout bytes.Buffer
	if code := runEval([]string{"run", "--json", root}, &out, &errout); code != 1 || errout.Len() != 0 {
		t.Fatal(code, out.String(), errout.String())
	}
	var r corpus.Report
	if e := json.Unmarshal(out.Bytes(), &r); e != nil || r.GateFailures != 1 || r.ExpectedFailures != 0 {
		t.Fatal(e, r.GateFailures)
	}
}
