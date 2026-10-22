package explain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/detect/pasted"
)

func TestGolden(t *testing.T) {
	for _, tc := range []struct {
		name    string
		history audit.History
	}{
		{"empty", audit.History{Records: []audit.Record{}}},
		{"prompt", audit.History{Session: "prompt-session", Records: []audit.Record{
			{TS: time.Date(2026, 10, 22, 15, 0, 0, 0, time.UTC), Tool: "prompt", Hook: "UserPromptSubmit", Decision: "observe", Rule: "prompt.telemetry", Reason: "Prompt presentation and pasted-content hints recorded; no enforcement.", Hidden: &hidden.Report{Findings: []hidden.Finding{{Type: "zero-width", Count: 1, Excerpt: "<U+200B>"}}}, Pasted: &pasted.Report{FencedBlocks: 1, LogLines: 40, LongLog: true}},
		}}},
		{"hidden", audit.History{Session: "hidden-session", Records: []audit.Record{
			{TS: time.Date(2026, 10, 22, 14, 2, 0, 0, time.UTC), Tool: "WebFetch", Hook: "PostToolUse", Decision: "allow", Rule: "source.web", Reason: "WebFetch returned untrusted content.", StateKnown: true, Tainted: true, TaintSources: []string{"web"}, Hidden: &hidden.Report{BytesScanned: 1048576, Truncated: true, Findings: []hidden.Finding{{Type: "zero-width", Count: 2, Excerpt: "<U+200B>"}}}},
		}}},
		{"tainted", audit.History{Session: "example-session", Asks: 1, Records: []audit.Record{
			{TS: time.Date(2026, 10, 21, 14, 1, 0, 0, time.UTC), Tool: "Read", Hook: "PreToolUse", Decision: "allow", Rule: "default.allow", Reason: "No applicable built-in risk rule matched.", StateKnown: true},
			{TS: time.Date(2026, 10, 21, 14, 2, 0, 0, time.UTC), Tool: "Bash", Hook: "PreToolUse", Decision: "ask", Rule: "TW002", Reason: "Destination example.com is outside the allowlist.", StateKnown: true, Tainted: true, TaintSources: []string{"web"}},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			if e := Render(&b, tc.history, false); e != nil {
				t.Fatal(e)
			}
			want, e := os.ReadFile(filepath.Join("..", "..", "testdata", "explain", tc.name+".golden"))
			if e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(b.Bytes(), want) {
				t.Fatalf("got:\n%s\nwant:\n%s", b.Bytes(), want)
			}
			b.Reset()
			if e = Render(&b, tc.history, true); e != nil {
				t.Fatal(e)
			}
			var h audit.History
			if e = json.Unmarshal(b.Bytes(), &h); e != nil || len(h.Records) != len(tc.history.Records) {
				t.Fatalf("invalid JSON: %s %v", b.Bytes(), e)
			}
		})
	}
}
