package hookio

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

// ResponseText collects JSON string values (never keys) from an opaque response
// in document order. No tool-specific result schema is assumed. Newlines separate
// values so adjacent blocks cannot manufacture a word or markup delimiter.
// The returned prefix is capped; the existing hook decoder caps the source JSON.
func (in PostToolUseInput) ResponseText(limit int) (string, bool) {
	if limit <= 0 {
		return "", len(in.ToolResponse) > 0
	}
	d := json.NewDecoder(bytes.NewReader(in.ToolResponse))
	d.UseNumber() // Arbitrarily large metadata numbers must not stop text scanning.
	type frame struct{ object, key bool }
	var stack []frame
	var b strings.Builder
	for {
		t, err := d.Token()
		if err == io.EOF {
			return b.String(), false
		}
		if err != nil {
			return b.String(), true
		}
		if delim, ok := t.(json.Delim); ok {
			if delim == '}' || delim == ']' {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				continue
			}
			if len(stack) > 0 && stack[len(stack)-1].object {
				stack[len(stack)-1].key = true
			}
			stack = append(stack, frame{object: delim == '{', key: delim == '{'})
			continue
		}
		if len(stack) > 0 && stack[len(stack)-1].object {
			f := &stack[len(stack)-1]
			if f.key {
				f.key = false
				continue
			}
			f.key = true
		}
		s, ok := t.(string)
		if !ok || s == "" {
			continue
		}
		if b.Len() > 0 {
			if b.Len() == limit {
				return b.String(), true
			}
			b.WriteByte('\n')
		}
		n := limit - b.Len()
		if len(s) > n {
			for n > 0 && !utf8.RuneStart(s[n]) {
				n--
			}
			b.WriteString(s[:n])
			return b.String(), true
		}
		b.WriteString(s)
	}
}
