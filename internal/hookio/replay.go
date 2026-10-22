package hookio

import (
	"bytes"
	"encoding/json"
	"strings"
)

// RemapReplay maps canonical fixture roots consistently in hook string values.
// It never interprets shell commands or writes proposed tool files. Only the
// evaluation harness uses this; runtime hook inputs are never rewritten.
func RemapReplay(payload []byte, replacements *strings.Replacer) ([]byte, error) {
	var v any
	d := json.NewDecoder(bytes.NewReader(payload))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			return replacements.Replace(x)
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for k, y := range x {
				x[k] = walk(y)
			}
		}
		return v
	}
	return json.Marshal(walk(v))
}

// Permission returns the normalized action; abstention is allow for evaluation
// purposes only. It does not create an explicit Claude permission approval.
func (r Result) Permission() string {
	switch r.kind {
	case ask:
		return "ask"
	case deny:
		return "deny"
	default:
		return "allow"
	}
}
