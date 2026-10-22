//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/valuematch"
)

func TestPostExtractsOnlyTaintingSources(t *testing.T) {
	for _, tc := range []struct {
		tool, args string
		tainted    bool
	}{
		{"WebFetch", `{}`, true}, {"WebSearch", `{}`, true}, {"mcp__search__query", `{}`, true},
		{"Bash", `{"command":"curl https://docs.example"}`, true},
		{"Read", `{"file_path":"/project/node_modules/pkg/README.md"}`, true},
		{"Read", `{"file_path":"/project/src/main.go"}`, false},
	} {
		t.Run(tc.tool+tc.args, func(t *testing.T) {
			home := postHome(t)
			body := strings.Replace(postPayload(tc.tool, tc.args), `"public":"opaque"`, `"public":"https://collector.example/unique"`, 1)
			if !tc.tainted {
				project := t.TempDir()
				if e := os.MkdirAll(filepath.Join(project, "src"), 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(project, "src", "main.go"), []byte("package main"), 0600); e != nil {
					t.Fatal(e)
				}
				body = strings.ReplaceAll(body, "/project", project)
				// The real project fixture is under /tmp; exclude test temp roots
				// explicitly rather than relying on an unresolved virtual Read.
				dir := filepath.Join(os.Getenv("HOME"), ".config", "taintwatch")
				if e := os.MkdirAll(dir, 0700); e != nil {
					t.Fatal(e)
				}
				if e := os.WriteFile(filepath.Join(dir, "policy.yaml"), []byte("version: 1\nsources:\n  read:\n    temp_paths:\n      replace: []\n"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			var out, errout bytes.Buffer
			if code := run([]string{"hook", "post"}, strings.NewReader(body), &out, &errout); code != 0 || errout.Len() != 0 {
				t.Fatal(code, errout.String())
			}
			store, e := state.New(state.Options{Home: home})
			if e != nil {
				t.Fatal(e)
			}
			s, e := store.Load("post-session")
			if e != nil {
				t.Fatal(e)
			}
			if tc.tainted {
				if len(s.TaintEvents) != 1 || len(s.TaintEvents[0].ValueMatches) == 0 {
					t.Fatal(s)
				}
				for _, v := range s.TaintEvents[0].ValueMatches {
					if len(v.Text) > valuematch.MaxValueBytes || len(v.Variants) > valuematch.MaxVariants {
						t.Fatal("bounds")
					}
				}
			} else if len(s.TaintEvents) != 0 {
				t.Fatal("trusted read extracted values")
			}
			log, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if e != nil {
				t.Fatal(e)
			}
			if bytes.Contains(log, []byte("collector.example")) {
				t.Fatal("indicator leaked into audit")
			}
		})
	}
}
