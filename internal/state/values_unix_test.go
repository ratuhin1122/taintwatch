//go:build linux || darwin

package state

import (
	"github.com/ratuhin1122/taintwatch/internal/valuematch"
	"strings"
	"testing"
)

func TestBoundedPrecomputedValueState(t *testing.T) {
	store := testStore(t)
	e := testEvent("value state")
	e.ValueMatches = []valuematch.Value{{Kind: "url", Text: strings.Repeat("x", valuematch.MaxValueBytes+1)}}
	for i := 0; i < valuematch.MaxValues+10; i++ {
		e.ValueMatches = append(e.ValueMatches, valuematch.Value{Kind: "url", Text: "https://example.net/supplied", Variants: []string{"untrusted caller pattern"}})
	}
	if _, err := store.MarkTainted("values", e); err != nil {
		t.Fatal(err)
	}
	e.ValueMatches[1].Text = "caller mutated"
	s, err := store.Load("values")
	if err != nil {
		t.Fatal(err)
	}
	values := s.TaintEvents[0].ValueMatches
	if len(s.TaintEvents[0].Values) != len(values) {
		t.Fatal("missing original value view")
	}
	if len(values) != valuematch.MaxValues {
		t.Fatal("cap", len(values))
	}
	for _, v := range values {
		if v.Text != "https://example.net/supplied" || len(v.Variants) == 0 || len(v.Variants) > valuematch.MaxVariants {
			t.Fatal(v)
		}
		for _, p := range v.Variants {
			if p == "untrusted caller pattern" {
				t.Fatal("accepted caller encoding")
			}
		}
	}
	if _, err = store.Clear("values", "explicit clear", "tester"); err != nil {
		t.Fatal(err)
	}
	s, err = store.Load("values")
	if err != nil || len(s.TaintEvents) != 0 {
		t.Fatal(s, err)
	}
}
