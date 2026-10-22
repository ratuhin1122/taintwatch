package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/rules"
)

func TestReplaySnapshotRedaction(t *testing.T) {
	snapshot := &rules.Snapshot{Version: 1, Fingerprint: strings.Repeat("a", 64), Matches: []string{"TW001", "Bearer privatevalue12345"}}
	sink := &memorySink{}
	if e := Write(sink, Record{Replay: snapshot, InputSummary: "full payload must be omitted"}); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(sink.data), "privatevalue") || strings.Contains(string(sink.data), "full payload") {
		t.Fatal(string(sink.data))
	}
	var r Record
	if e := json.Unmarshal(sink.data, &r); e != nil || r.Replay == nil || r.Replay.Matches[0] != "TW001" {
		t.Fatal(r, e)
	}
	if snapshot.Matches[1] != "Bearer privatevalue12345" {
		t.Fatal("mutated caller snapshot")
	}
	r, e := DecodeRecord([]byte(`{"hook":"PreToolUse","input_summary":"accidental raw body","tool_input":{"secret":"omitted"},"reason":"Bearer privatevalue12345"}`))
	if e != nil || strings.Contains(r.Reason, "privatevalue") || r.InputSummary != "tool arguments and response omitted" {
		t.Fatal(r, e)
	}
}
