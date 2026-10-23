package audit

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
)

func TestHiddenAudit(t *testing.T) {
	report := hidden.Scan(("<!-- " + fakeCredential("Bearer ", "private-content-do-not-log") + " --> \u200b раypal"))
	sink := &memorySink{}
	if err := Write(sink, Record{Session: "s", Decision: "allow", Hidden: &report}); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"private-content-do-not-log", "раypal", "\u200b"} {
		if strings.Contains(string(sink.data), s) {
			t.Fatalf("unsafe audit: %s", sink.data)
		}
	}
	var r Record
	if err := json.Unmarshal(sink.data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Decision != "allow" || r.Hidden == nil || len(r.Hidden.Findings) != 3 || r.Hidden.Findings[0].Excerpt != "<U+200B>" {
		t.Fatalf("record %+v", r)
	}
	// Defense in depth for caller-supplied excerpts, including terminal controls.
	report = hidden.Report{Findings: []hidden.Finding{{Type: "test", Count: 1, Excerpt: (fakeCredential("Bearer ", "secretvalue12345") + "\u202e\x1b")}}}
	if err := Write(sink, Record{Hidden: &report}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sink.data), "secretvalue") || strings.Contains(string(sink.data), "\u202e") {
		t.Fatalf("redaction failed: %s", sink.data)
	}
	if !strings.Contains(report.Findings[0].Excerpt, "secretvalue") {
		t.Fatal("mutated caller report")
	}
}
