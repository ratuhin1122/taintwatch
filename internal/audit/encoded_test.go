package audit

import (
	"github.com/ratuhin1122/taintwatch/internal/detect/encoded"
	"strings"
	"testing"
)

func TestEncodedMetadataRedactionAndIsolation(t *testing.T) {
	e := &encoded.Report{Findings: []encoded.Finding{{Encoding: "Bearer privatevalue12345", Type: "token=privatevalue12345", Count: 1}}}
	sink := &memorySink{}
	if err := Write(sink, Record{Encoded: e}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sink.data), "privatevalue12345") {
		t.Fatal("leaked metadata")
	}
	if !strings.Contains(e.Findings[0].Encoding, "privatevalue12345") {
		t.Fatal("mutated caller report")
	}
}
