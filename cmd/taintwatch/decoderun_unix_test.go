//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestTW007HookIntegration(t *testing.T) {
	for _, tc := range []struct {
		command string
		ask     bool
	}{
		{`base64 -D f | ruby`, true},
		{`openssl enc -d -in f | python`, true},
		{`source <(xxd -r -p f)`, true},
		{`bash -c "$(base64 -d f)"`, true},
		{`python -c 'exec(base64.b64decode(x))'`, true},
		{`node -e 'eval(Buffer.from(x,"base64").toString())'`, true},
		{`bash <<<"$(base64 -d f)"`, true},
		{`eval "$(echo "$(base64 -d f)")"`, true},
		{`base64 -d file.b64 > out.bin`, false},
		{`base64 -d f > out; echo safe | bash`, false},
		{`python -c 'print(base64.b64decode(x))'`, false},
		{`echo 'base64 -d f | bash'`, false},
	} {
		t.Run(tc.command, func(t *testing.T) {
			home := postHome(t)
			var out, errOut bytes.Buffer
			payload := prePayload("Bash", `{"command":`+strconv.Quote(tc.command)+`}`)
			code := run([]string{"hook", "pre"}, strings.NewReader(payload), &out, &errOut)
			if code != 0 || errOut.Len() != 0 || strings.Contains(out.String(), `"permissionDecision":"ask"`) != tc.ask {
				t.Fatal(code, out.String(), errOut.String())
			}
			log, e := os.ReadFile(filepath.Join(home, "audit.jsonl"))
			if e != nil || strings.Contains(string(log), `"rule":"TW007"`) != tc.ask {
				t.Fatal(string(log), e)
			}
			if tc.ask && !strings.Contains(out.String(), "This command decodes data and executes it") {
				t.Fatal(out.String())
			}
		})
	}
}
