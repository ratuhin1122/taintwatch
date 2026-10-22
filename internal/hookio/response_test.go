package hookio

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResponseText(t *testing.T) {
	for _, tc := range []struct {
		json      string
		limit     int
		want      string
		truncated bool
	}{
		{`"hello\u200b"`, 100, "hello\u200b", false},
		{`{"key-not-content":{"text":"one"},"content":[{"type":"text","text":"two"},"three"],"ok":true}`, 100, "one\ntext\ntwo\nthree", false},
		{`null`, 100, "", false}, {`[]`, 100, "", false},
		{`[1e10000,{"text":"hidden\u200b"}]`, 100, "hidden\u200b", false},
		{`["abcd","efg"]`, 5, "abcd\n", true},
		{`"abcd漢"`, 5, "abcd", true},
		{`"abcd"`, 4, "abcd", false},
	} {
		t.Run(tc.json, func(t *testing.T) {
			in := PostToolUseInput{ToolResponse: json.RawMessage(tc.json)}
			s, tr := in.ResponseText(tc.limit)
			if s != tc.want || tr != tc.truncated {
				t.Fatalf("%q %v", s, tr)
			}
		})
	}
	in := PostToolUseInput{ToolResponse: json.RawMessage(`{"` + strings.Repeat("x", 1000) + `":"safe"}`)}
	if s, _ := in.ResponseText(100); s != "safe" {
		t.Fatal(s)
	}
}
