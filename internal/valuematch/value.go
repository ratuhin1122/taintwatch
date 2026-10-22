// Package valuematch tracks bounded exact and encoded provenance indicators.
// It does not infer semantic equivalence or execute/recursively decode content.
package valuematch

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

const (
	MaxTextBytes     = 1 << 20
	MaxValues        = 32
	MaxValueBytes    = 256
	MaxVariants      = 32
	MaxSessionValues = 64
	MaxPatternBytes  = 128 << 10
)

// Value contains an original indicator and precomputed bounded encodings.
type Value struct {
	Kind     string   `json:"kind"`
	Text     string   `json:"text"`
	Variants []string `json:"variants"`
}

// Valid permits short IPv6 literals such as ::1 while excluding generic short
// words/paths whose substring encodings would be excessively broad.
func Valid(v Value) bool {
	return len(v.Text) <= MaxValueBytes && (len(v.Text) >= 4 || v.Kind == "ip" && net.ParseIP(v.Text) != nil)
}

// Extract scans a bounded response prefix. Order and deduplication are stable.
func Extract(text string) []Value {
	if len(text) > MaxTextBytes {
		text = text[:MaxTextBytes]
	}
	values := []Value{}
	seen := map[string]bool{}
	add := func(kind, s string) {
		if len(values) >= MaxValues || !Valid(Value{Kind: kind, Text: s}) || seen[s] {
			return
		}
		seen[s] = true
		values = append(values, Value{Kind: kind, Text: s, Variants: Variants(s)})
	}
	// FieldsFunc is linear and the input prefix bounds token allocation.
	for _, raw := range strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("\"'`<>(){},", r)
	}) {
		if len(values) >= MaxValues {
			break
		}
		if len(raw) > MaxValueBytes+32 {
			continue
		}
		s := strings.TrimRight(raw, ".,;!?")
		if i := strings.Index(s, "="); i >= 0 && !strings.Contains(s[:i], "/") {
			s = s[i+1:]
		}
		if u, e := url.Parse(s); e == nil && u.Hostname() != "" && u.Scheme != "" {
			add("url", s)
			if net.ParseIP(u.Hostname()) != nil {
				add("ip", u.Hostname())
			} else {
				add("host", u.Hostname())
			}
			continue
		}
		if strings.Contains(s, "@") {
			parts := strings.Split(s, "@")
			if len(parts) == 2 && parts[0] != "" && hostname(parts[1]) {
				add("email", s)
				add("host", parts[1])
				continue
			}
		}
		host := strings.Trim(s, "[]")
		if h, _, e := net.SplitHostPort(s); e == nil {
			host = h
		}
		if net.ParseIP(host) != nil {
			add("ip", host)
			continue
		}
		if strings.ContainsAny(s, "/\\") && !strings.Contains(s, "...") && strings.IndexFunc(s, unicode.IsLetter) >= 0 {
			add("path", s)
			continue
		}
		if strings.HasPrefix(s, ".") && len(s) > 2 {
			add("path", s)
			continue
		}
		if hostname(host) {
			add("host", host)
		}
	}
	return values
}

func hostname(s string) bool {
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	parts := strings.Split(s, ".")
	for _, p := range parts {
		if len(p) == 0 || len(p) > 63 || p[0] == '-' || p[len(p)-1] == '-' {
			return false
		}
		for _, r := range p {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	last := parts[len(parts)-1]
	return len(last) >= 2 && strings.IndexFunc(last, unicode.IsLetter) >= 0
}

// Variants includes standalone padded/unpadded encodings and base64 cores for
// all three byte alignments. Unknown preceding/trailing bits are trimmed, so
// the stable interior matches inside an encoding of a larger byte sequence.
func Variants(s string) []string {
	if len(s) < 2 || len(s) > MaxValueBytes {
		return nil
	}
	out := []string{}
	seen := map[string]bool{s: true}
	add := func(v string) {
		if v != "" && !seen[v] && len(out) < MaxVariants {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		b := enc.EncodeToString([]byte(s))
		add(b)
		add(strings.TrimRight(b, "="))
		for offset := 0; offset < 3; offset++ {
			b = enc.EncodeToString(append(make([]byte, offset), []byte(s)...))
			start := (offset*8 + 5) / 6
			end := (offset + len(s)) * 8 / 6
			if end-start >= 2 {
				add(b[start:end])
			}
		}
	}
	add(url.QueryEscape(s))
	add(url.PathEscape(s))
	lowerEscapes := func(s string) string {
		b := []byte(s)
		for i := 0; i+2 < len(b); i++ {
			if b[i] == '%' {
				copy(b[i+1:i+3], strings.ToLower(string(b[i+1:i+3])))
				i += 2
			}
		}
		return string(b)
	}
	add(lowerEscapes(url.QueryEscape(s)))
	add(lowerEscapes(url.PathEscape(s)))
	// Fully percent-escaped bytes cover encoders that also escape safe characters.
	var pct, dec, hx strings.Builder
	for _, b := range []byte(s) {
		pct.WriteByte('%')
		pct.WriteString(strings.ToUpper(hex.EncodeToString([]byte{b})))
	}
	add(pct.String())
	add(strings.ToLower(pct.String()))
	add(hex.EncodeToString([]byte(s)))
	add(strings.ToUpper(hex.EncodeToString([]byte(s))))
	add(html.EscapeString(s))
	for _, r := range s {
		dec.WriteString("&#" + strconv.Itoa(int(r)) + ";")
		hx.WriteString("&#x" + strconv.FormatInt(int64(r), 16) + ";")
	}
	add(dec.String())
	add(hx.String())
	add(strings.ReplaceAll(hx.String(), "&#x", "&#X"))
	return out
}

// DomainOnlyAllowed suppresses bare allowed hosts and origin-only URLs, never
// a full URL path/query, email target or file path on that host.
func DomainOnlyAllowed(v Value, domains []string) bool {
	host := ""
	if v.Kind == "host" || v.Kind == "ip" {
		host = v.Text
	}
	if v.Kind == "url" {
		u, e := url.Parse(v.Text)
		if e == nil && (u.Path == "" || u.Path == "/") && u.RawQuery == "" && u.Fragment == "" && u.User == nil {
			host = u.Hostname()
		}
	}
	for _, d := range domains {
		if host != "" && strings.EqualFold(strings.TrimSuffix(host, "."), strings.TrimSuffix(d, ".")) {
			return true
		}
	}
	return false
}
