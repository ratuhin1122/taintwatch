package hookio

import (
	"bytes"
	"strings"
	"testing"
)

func TestReplayRemapping(t *testing.T) {
	b := []byte(`{"session_id":"s","cwd":"/workspace/project","hook_event_name":"PostToolUse","tool_name":"WebFetch","tool_input":{},"tool_response":{"n":1e10000,"text":"/workspace/project/README.md","content":["unchanged"]}}`)
	mapped, err := RemapReplay(b, strings.NewReplacer("/workspace/project", "/private/project"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(mapped, []byte("1e10000")) || !bytes.Contains(mapped, []byte("/private/project/README.md")) || !bytes.Contains(b, []byte("/workspace/project/README.md")) {
		t.Fatal(string(mapped))
	}
	if _, err = DecodePostToolUse(bytes.NewReader(mapped)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		r    Result
		want string
	}{{Result{}, "allow"}, {Allow(), "allow"}, {Ask("reason"), "ask"}, {Deny("reason"), "deny"}} {
		if tc.r.Permission() != tc.want {
			t.Fatal(tc.r.Permission(), tc.want)
		}
	}
}
