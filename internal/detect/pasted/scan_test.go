package pasted

import (
	"reflect"
	"strings"
	"testing"
)

func TestScan(t *testing.T) {
	for _, tc := range []struct {
		name, s         string
		blocks, logs    int
		long, truncated bool
	}{
		{"plain", "Please fix this function.", 0, 0, false, false},
		{"fenced", "Please review:\n```go\nfmt.Println(1)\n```", 1, 0, false, false},
		{"tildes", "~~~text\ntext\n~~~\n```sh\necho x\n```", 2, 0, false, false},
		{"nested fence", "````markdown\n```go\nx\n```\n````", 1, 0, false, false},
		{"unclosed", "```python\nprint(1)", 1, 0, false, false},
		{"indented", "   ```go\nx\n   ```", 1, 0, false, false},
		{"inline", "Use `fmt.Print` or ```ticks``` in a sentence.", 0, 0, false, false},
		{"deep indentation", "    ```", 0, 0, false, false},
		{"short logs", "INFO start\nERROR failed\n", 0, 2, false, false},
		{"timestamps", "2026-10-22 12:00:00 started\n12:00:01 done\n[worker] WARN slow\nmain.go:12: message", 0, 4, false, false},
		{"long logs", strings.Repeat("INFO "+strings.Repeat("x", 100)+"\n", 40), 0, 40, true, false},
		{"too short bytes", strings.Repeat("INFO x\n", 40), 0, 40, false, false},
		{"too few lines", strings.Repeat("INFO "+strings.Repeat("x", 300)+"\n", 20), 0, 20, false, false},
		{"long prose", strings.Repeat(strings.Repeat("words ", 30)+"\n", 50), 0, 0, false, false},
		{"minority logs", strings.Repeat("prose\n", 100) + strings.Repeat("INFO "+strings.Repeat("x", 100)+"\n", 40), 0, 40, false, false},
		{"cap", strings.Repeat("x", MaxBytes) + "\n```", 0, 0, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Scan(tc.s)
			if r.FencedBlocks != tc.blocks || r.LogLines != tc.logs || r.LongLog != tc.long || r.Truncated != tc.truncated || r.BytesScanned > MaxBytes {
				t.Fatalf("%+v", r)
			}
		})
	}
}

func FuzzScan(f *testing.F) {
	for _, s := range []string{"```go\nx\n```", "~~~\nINFO start\n~~~", "👩‍💻 中文", "[worker] WARN text", strings.Repeat("[", 200)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, b := Scan(s), Scan(s)
		if !reflect.DeepEqual(a, b) || a.BytesScanned > MaxBytes || a.BytesScanned > len(s) || a.LogLines < 0 || a.FencedBlocks < 0 {
			t.Fatalf("unbounded/nondeterministic %+v", a)
		}
	})
}
