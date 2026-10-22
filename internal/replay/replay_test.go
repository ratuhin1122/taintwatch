package replay

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
)

func TestGoldens(t *testing.T) {
	for _, name := range []string{"candidate", "matching-change"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "testdata", "replay")
			r, e := Run(filepath.Join(root, "audit.jsonl"), filepath.Join(root, name+".yaml"))
			if e != nil {
				t.Fatal(e)
			}
			var b bytes.Buffer
			if e = Render(&b, r); e != nil {
				t.Fatal(e)
			}
			want, e := os.ReadFile(filepath.Join(root, name+".golden"))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(b.Bytes(), want) {
				t.Fatalf("got:\n%s\nwant:\n%s", b.Bytes(), want)
			}
			if name == "candidate" && (r.Replayed != 6 || r.DecisionChanges != 4 || r.RuleChanges != 1 || r.Unchanged != 1 || len(r.Unreplayable) != 3 || r.Ignored != 2) {
				t.Fatalf("bad counts %+v", r)
			}
		})
	}
}

func TestMalformedAndLegacy(t *testing.T) {
	c := policy.Defaults()
	for _, text := range []string{"{}", "null\n", "{\n", `{"decision":42}` + "\n", strings.Repeat("x", (64<<10)+2) + "\n"} {
		if _, e := Compare(strings.NewReader(text), c); e == nil {
			t.Fatal("bad log accepted")
		}
	}
	legacy := `{"session":"old","hook":"PreToolUse","tool":"Bash","decision":"ask","rule":"TW002","state_known":true,"tainted":true,"evidence":["curl https://evil.example"],"input_summary":"raw contents must not be recovered"}` + "\n"
	r, e := Compare(strings.NewReader(legacy), c)
	if e != nil || r.Replayed != 0 || len(r.Unreplayable) != 1 {
		t.Fatal(r, e)
	}
	var b bytes.Buffer
	Render(&b, r)
	if strings.Contains(b.String(), "evil.example") || strings.Contains(b.String(), "raw contents") {
		t.Fatal("recovered omitted data")
	}
	if r, e = Compare(strings.NewReader(""), c); e != nil || r.Records != 0 {
		t.Fatal(r, e)
	}
	if got := display("name\u202e\x1b Bearer privatevalue12345"); strings.ContainsAny(got, "\u202e\x1b") || strings.Contains(got, "privatevalue") {
		t.Fatal(got)
	}
	for _, matches := range []string{"", `,"matches":null`} {
		text := fmt.Sprintf(`{"hook":"PreToolUse","decision":"allow","rule":"default.allow","state_known":true,"replay":{"version":2,"match_policy_sha256":%q%s}}`+"\n", rules.MatchFingerprint(c), matches)
		r, e = Compare(strings.NewReader(text), c)
		if e != nil || r.Replayed != 0 || len(r.Unreplayable) != 1 {
			t.Fatal("missing match vector inferred as empty", r, e)
		}
	}
}

func TestReadOnlyFilesAndNoAmbientConfig(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "replay")
	dir := t.TempDir()
	log := filepath.Join(dir, "audit.jsonl")
	candidate := filepath.Join(dir, "new.yaml")
	for _, p := range []struct{ from, to string }{{filepath.Join(root, "audit.jsonl"), log}, {filepath.Join(root, "candidate.yaml"), candidate}} {
		b, e := os.ReadFile(p.from)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p.to, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	beforeLog, _ := os.ReadFile(log)
	beforePolicy, _ := os.ReadFile(candidate)
	home := filepath.Join(dir, "never-created")
	t.Setenv("TAINTWATCH_HOME", home)
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "bad")
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "bad")
	if _, e := Run(log, candidate); e != nil {
		t.Fatal(e)
	}
	afterLog, _ := os.ReadFile(log)
	afterPolicy, _ := os.ReadFile(candidate)
	if !bytes.Equal(beforeLog, afterLog) || !bytes.Equal(beforePolicy, afterPolicy) {
		t.Fatal("input file changed")
	}
	if _, e := os.Stat(home); !os.IsNotExist(e) {
		t.Fatal("created state", e)
	}
	if _, e := Run(log, filepath.Join(dir, "missing")); e == nil {
		t.Fatal("missing policy accepted")
	}
	if _, e := Run(dir, candidate); e == nil {
		t.Fatal("directory accepted")
	}
	link := filepath.Join(dir, "link")
	if e := os.Symlink(log, link); e == nil {
		if _, e = Run(link, candidate); e == nil {
			t.Fatal("symlink log accepted")
		}
	}
}

func FuzzCompare(f *testing.F) {
	f.Add("{}\n")
	f.Add("null\n")
	f.Add(`{"hook":"PreToolUse","rule":"TW001","decision":"ask"}` + "\n")
	c := policy.Defaults()
	f.Fuzz(func(t *testing.T, s string) {
		r, e := Compare(strings.NewReader(s), c)
		if e == nil && (r.Records > maxRecords || r.Replayed+r.Ignored+len(r.Unreplayable) != r.Records) {
			t.Fatal("inconsistent counts")
		}
	})
}
