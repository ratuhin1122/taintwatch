package eval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func example(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile("../../eval/corpus/attacks/attack-01-secret-read.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestReviewBatch(t *testing.T) {
	s, err := Validate("../../eval/corpus")
	if err != nil {
		t.Fatal(err)
	}
	if s.Files != 50 || s.Attacks != 20 || s.Benign != 30 || s.KnownMisses != 3 || s.Expectations < 50 || s.Steps < 100 {
		t.Fatalf("unexpected review batch %+v", s)
	}
	for _, kind := range []string{"attacks", "benign"} {
		files, err := filepath.Glob("../../eval/corpus/" + kind + "/*.json")
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range files {
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			v, err := Decode(bytes.NewReader(b))
			if err != nil || v.Provenance.Kind != "original" || v.License != "MIT" {
				t.Fatal(path, v.Provenance, err)
			}
		}
	}
}

func TestDecodeInvalid(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(map[string]any)
	}{
		{"unknown key", "unknown field", func(m map[string]any) { m["descripton"] = "typo" }},
		{"version", "schema_version", func(m map[string]any) { m["schema_version"] = 2 }},
		{"id", "id/category", func(m map[string]any) { m["id"] = "../../escape" }},
		{"license", "license", func(m map[string]any) { m["license"] = "All rights reserved" }},
		{"source", "provenance", func(m map[string]any) { delete(m, "provenance") }},
		{"derived without URL", "https", func(m map[string]any) { m["provenance"].(map[string]any)["kind"] = "permissive-derived" }},
		{"target", "target", func(m map[string]any) { m["target"] = "M99" }},
		{"M4 unmarked", "M4", func(m map[string]any) { m["target"] = "M4" }},
		{"miss without reason", "known_miss", func(m map[string]any) { m["known_miss"] = true }},
		{"reason without miss", "known_miss", func(m map[string]any) { m["known_miss_reason"] = "not tagged" }},
		{"no steps", "steps", func(m map[string]any) { m["steps"] = []any{} }},
		{"step typo", "unknown field", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["exepct"] = map[string]any{"decision": "ask"}
		}},
		{"duplicate step id", "unique", func(m map[string]any) {
			ss := m["steps"].([]any)
			ss[1].(map[string]any)["id"] = ss[0].(map[string]any)["id"]
		}},
		{"event", "event must", func(m map[string]any) { m["steps"].([]any)[0].(map[string]any)["event"] = "UserPromptSubmit" }},
		{"event mismatch", "envelope", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["payload"].(map[string]any)["hook_event_name"] = "PostToolUse"
		}},
		{"session", "session_id", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["payload"].(map[string]any)["session_id"] = "other"
		}},
		{"cwd", "cwd", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["payload"].(map[string]any)["cwd"] = "/actual/host"
		}},
		{"argument shape", "tool arguments", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["payload"].(map[string]any)["tool_input"] = map[string]any{"file_path": 42}
		}},
		{"missing response", "tool_response", func(m map[string]any) {
			delete(m["steps"].([]any)[1].(map[string]any)["payload"].(map[string]any), "tool_response")
		}},
		{"post expectation", "only on PreToolUse", func(m map[string]any) {
			m["steps"].([]any)[1].(map[string]any)["expect"] = map[string]any{"decision": "allow"}
		}},
		{"bad decision", "allow, ask, or deny", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["expect"].(map[string]any)["decision"] = "block"
		}},
		{"bad rule", "expect.rule", func(m map[string]any) {
			m["steps"].([]any)[0].(map[string]any)["expect"].(map[string]any)["rule"] = "TW1"
		}},
		{"no scoring after source", "sequence requires", func(m map[string]any) { delete(m["steps"].([]any)[2].(map[string]any), "expect") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m map[string]any
			if err := json.Unmarshal(example(t), &m); err != nil {
				t.Fatal(err)
			}
			tc.mutate(m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Decode(bytes.NewReader(b)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v; want %s", err, tc.want)
			}
		})
	}
	for _, s := range []string{`null`, `[]`, `{} {}`, `{"id":"a","id":"b"}`, strings.Repeat("[", 65) + strings.Repeat("]", 65), strings.Repeat("x", MaxFileBytes+1)} {
		if _, err := Decode(strings.NewReader(s)); err == nil {
			t.Fatal("accepted invalid input")
		}
	}
}

func TestCorpusPaths(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*testing.T, string)
	}{
		{"wrong filename", func(t *testing.T, root string) {
			if err := os.Rename(filepath.Join(root, "attacks", "attack-01-secret-read.json"), filepath.Join(root, "attacks", "wrong.json")); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra extension", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "benign", "typo.yaml"), []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate id", func(t *testing.T, root string) {
			if err := os.WriteFile(filepath.Join(root, "benign", "attack-01-secret-read.json"), example(t), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown directory", func(t *testing.T, root string) {
			if err := os.Mkdir(filepath.Join(root, "attackz"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			for _, kind := range []string{"attacks", "benign"} {
				if err := os.Mkdir(filepath.Join(root, kind), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(root, "attacks", "attack-01-secret-read.json"), example(t), 0600); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile("../../eval/corpus/benign/benign-01-go-tests.json")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(root, "benign", "benign-01-go-tests.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = Validate(root); err != nil {
				t.Fatal(err)
			}
			tc.change(t, root)
			if _, err = Validate(root); err == nil {
				t.Fatal("accepted malformed corpus")
			}
		})
	}
	root := t.TempDir()
	if _, err := Validate(root); err == nil {
		t.Fatal("accepted empty corpus")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(root, link); err == nil {
		if _, err = Validate(link); err == nil {
			t.Fatal("accepted symlink root")
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(example(f))
	f.Add([]byte(`{"schema_version":1}`))
	f.Add([]byte(`{"a":{"x":1,"x":2}}`))
	f.Add([]byte(`]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := Decode(bytes.NewReader(b))
		if err == nil && (s.SchemaVersion != 1 || len(s.Steps) < 2 || len(s.Steps) > 256) {
			t.Fatal("invalid accepted scenario")
		}
	})
}
