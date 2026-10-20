package hookio

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestOutputGoldens(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result Result
	}{
		{"allow", Allow()},
		{"ask", Ask("Please approve this action.")},
		{"deny", Deny("Policy explicitly denies this action.")},
		{"context", AdditionalContext("This session read untrusted content.")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "hookio", "outputs", tc.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code, err := tc.result.Write(&out)
			if err != nil || code != 0 || tc.result.ExitCode() != 0 || !bytes.Equal(out.Bytes(), want) {
				t.Fatalf("code=%d err=%v\ngot %q\nwant %q", code, err, out.Bytes(), want)
			}
		})
	}
}
