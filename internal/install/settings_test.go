package install

import (
	"bytes"
	"encoding/json"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSettingsRoundTrip(t *testing.T) {
	for _, initial := range []string{`{}`, `{"hooks":{}}`, `{"hooks":{"PreToolUse":[]}}`, `{"model":"example","hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"echo unrelated"}]}],"Stop":[]}}`} {
		t.Run(initial, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "settings.json")
			if e := os.WriteFile(p, []byte(initial), 0600); e != nil {
				t.Fatal(e)
			}
			changed, backup, e := Change(p, "/opt/taint watch/taintwatch", false)
			if e != nil || !changed {
				t.Fatal(changed, e)
			}
			b, e := os.ReadFile(backup)
			if e != nil || string(b) != initial {
				t.Fatal("backup", e, string(b))
			}
			if !Wired(p, "/opt/taint watch/taintwatch") {
				t.Fatal("not wired")
			}
			after, _ := os.ReadFile(p)
			changed, backup, e = Change(p, "/opt/taint watch/taintwatch", false)
			if e != nil || changed || backup != "" {
				t.Fatal("not idempotent", changed, e)
			}
			again, _ := os.ReadFile(p)
			if !bytes.Equal(after, again) {
				t.Fatal("changed bytes")
			}
			changed, _, e = Change(p, "ignored", true)
			if e != nil || !changed {
				t.Fatal(changed, e)
			}
			got, _, e := readObject(p)
			want := map[string]any{}
			_ = jsonDecode(initial, &want)
			if e != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("roundtrip got %#v want %#v: %v", got, want, e)
			}
			changed, _, e = Change(p, "ignored", true)
			if e != nil || changed {
				t.Fatal(changed, e)
			}
		})
	}
}
func jsonDecode(s string, v *map[string]any) error { // same bounded reader semantics, without a fixture file
	return json.Unmarshal([]byte(s), v)
}
func TestUninstallPreservesEditsAndUnownedEntries(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	entries := HookEntries("/bin/tw")
	v := map[string]any{"hooks": map[string]any{"PreToolUse": []any{entries["PreToolUse"]}}}
	if e := os.WriteFile(p, encode(v), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Change(p, "/bin/tw", false); e != nil {
		t.Fatal(e)
	}
	v, _, _ = readObject(p)
	h := v["hooks"].(map[string]any)
	h["PostToolUse"].([]any)[0].(map[string]any)["matcher"] = "Read"
	_ = os.WriteFile(p, encode(v), 0600)
	_, _, e := Change(p, "", true)
	if e != nil {
		t.Fatal(e)
	}
	got, _, _ := readObject(p)
	delete(h, "UserPromptSubmit") // The untouched owned telemetry hook is removed.
	if !reflect.DeepEqual(v, got) {
		t.Fatal("removed user edited or preexisting hook")
	}
}
func TestInvalidSettings(t *testing.T) {
	for _, s := range []string{`null`, `[]`, `{"hooks":[]}`, `{"hooks":{"PreToolUse":{}}}`, `{} {}`, `{"a":`} {
		t.Run(s, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "settings.json")
			_ = os.WriteFile(p, []byte(s), 0600)
			if _, _, e := Change(p, "/bin/tw", false); e == nil {
				t.Fatal("accepted invalid")
			}
			b, _ := os.ReadFile(p)
			if string(b) != s {
				t.Fatal("modified invalid settings")
			}
		})
	}
}
func TestSettingsPath(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir())
	p, e := SettingsPath()
	if e != nil || p != filepath.Join(os.Getenv("CLAUDE_CONFIG_DIR"), "settings.json") {
		t.Fatal(p, e)
	}
}

func TestCreatedSettingsRemoval(t *testing.T) {
	p := filepath.Join(t.TempDir(), "settings.json")
	if _, _, e := Change(p, "/bin/tw", false); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Change(p, "", true); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(p); !os.IsNotExist(e) {
		t.Fatal("new empty settings file retained", e)
	}
}
func TestDoctorGolden(t *testing.T) {
	var out bytes.Buffer
	checks := []Check{{"PASS", "binary", "version 0.1.0"}, {"WARN", "hooks", "verify plugin hooks with /hooks"}, {"FAIL", "state", "use WSL"}, {"PASS", "dry-run", "WebFetch taints; Read .env requires confirmation (in memory)"}}
	if !RenderDoctor(&out, checks) {
		t.Fatal("failure lost")
	}
	want, e := os.ReadFile("../../testdata/doctor/report.txt")
	if e != nil || out.String() != string(want) {
		t.Fatalf("%v\n%s", e, out.String())
	}
}
func TestDryRun(t *testing.T) {
	p := policy.Defaults()
	if e := DryRun(p); e != nil {
		t.Fatal(e)
	}
	p.Sources.Tools = nil
	if e := DryRun(p); e == nil || !strings.Contains(e.Error(), "TW001") {
		t.Fatal("weakened policy not noticed", e)
	}
}
