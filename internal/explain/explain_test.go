package explain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
)

func TestGolden(t *testing.T) {
	for _, tc := range []struct {
		name    string
		history audit.History
	}{
		{"empty", audit.History{Records: []audit.Record{}}},
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
