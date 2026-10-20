package hookio

import (
	"strings"
	"testing"
)

func TestSourceArguments(t *testing.T) {
	for _, tc := range []struct {
		tool, args, command, path string
		bad                       bool
	}{
		{"Bash", `{"command":"curl example.com","future":true}`, "curl example.com", "", false},
		{"Read", `{"file_path":"/project/file","offset":1}`, "", "/project/file", false},
		{"Bash", `{}`, "", "", true}, {"Bash", `{"command":42}`, "", "", true},
		{"Read", `{"file_path":null}`, "", "", true}, {"Read", `{"file_path":""}`, "", "", true},
		{"WebFetch", `{}`, "", "", false},
	} {
		t.Run(tc.tool+tc.args, func(t *testing.T) {
			payload := `{"session_id":"documented","hook_event_name":"PostToolUse","tool_name":"` + tc.tool + `","tool_input":` + tc.args + `,"tool_response":null}`
			in, err := DecodePostToolUse(strings.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			args, err := in.SourceArguments()
			if (err != nil) != tc.bad || args.Command != tc.command || args.FilePath != tc.path {
				t.Fatalf("args=%+v err=%v", args, err)
			}
		})
	}
}
