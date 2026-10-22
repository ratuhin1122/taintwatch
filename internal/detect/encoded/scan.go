// Package encoded performs bounded one-level decoding for informational hints.
// It never produces a permission decision or returns decoded contents.
package encoded

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MaxBytes        = 1 << 20
	MaxBlobBytes    = 16 << 10
	MaxDecodedBytes = 64 << 10
	MaxBlobs        = 32
	MinBlobBytes    = 8
)

type Finding struct {
	Encoding string `json:"encoding"`
	Type     string `json:"type"`
	Count    int    `json:"count"`
}
type Report struct {
	BytesScanned int       `json:"bytes_scanned"`
	Candidates   int       `json:"candidates"`
	DecodedBlobs int       `json:"decoded_blobs"`
	DecodedBytes int       `json:"decoded_bytes"`
	TextBlobs    int       `json:"text_blobs"`
	Skipped      int       `json:"skipped"`
	Truncated    bool      `json:"truncated"`
	LimitReached bool      `json:"limit_reached"`
	Findings     []Finding `json:"findings,omitempty"`
}

// Scan advances through a bounded prefix. Oversized blobs are skipped whole,
// never decoded from a misleading truncated prefix. Decoded text is never
// submitted to Scan again: nested encodings are deliberately out of scope.
func Scan(text string) Report {
	return ScanPrefix(text, false)
}

// ScanPrefix accepts upstream truncation information so a blob cut by response
// string extraction cannot be mistaken for a complete unpadded encoding.
func ScanPrefix(text string, truncated bool) Report {
	r := Report{Truncated: truncated}
	reserved := 0
	if len(text) > MaxBytes {
		text = text[:MaxBytes]
		r.Truncated = true
	}
	r.BytesScanned = len(text)
	if sourceMap(text) {
		r.Skipped++
		return r
	}
	i := 0
	for i < len(text) {
		// Image/source-map data URIs must be recognized before generic tokens
		// split their MIME header away from their encoded body.
		uri := i
		if p := strings.IndexByte(text[i:min(len(text), i+64)], '='); p > 0 && identifier(text[i:i+p]) {
			uri = i + p + 1
		}
		if prefixFold(text[uri:], "data:image/") || prefixFold(text[uri:], "data:application/json") && strings.Contains(text[max(0, uri-80):uri], "sourceMappingURL=") {
			end := uri
			for end < len(text) && !uriEnd(text[end]) {
				end++
			}
			r.Skipped++
			i = end
			continue
		}
		if !tokenChar(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && tokenChar(text[i]) {
			i++
		}
		// A blob cut by the global prefix cap has no trustworthy ending.
		if r.Truncated && i == len(text) {
			r.LimitReached = true
			break
		}
		token := strings.TrimRight(text[start:i], ".")
		if p := strings.IndexByte(token, '='); p >= 0 && p < len(token)-2 && identifier(token[:p]) {
			token = token[p+1:]
		}
		if knownToken(token) {
			r.Skipped++
			continue
		}
		if strings.HasPrefix(token, "0x") || strings.HasPrefix(token, "0X") {
			token = token[2:]
		}
		if len(token) < MinBlobBytes || !alphabet(token) {
			continue
		}
		if r.Candidates == MaxBlobs {
			r.LimitReached = true
			break
		}
		r.Candidates++
		if len(token) > MaxBlobBytes {
			r.Skipped++
			r.LimitReached = true
			continue
		}
		kind := "base64"
		var b []byte
		var err error
		estimate := len(strings.TrimRight(token, "=")) * 6 / 8
		if hexToken(token) && len(token)%2 == 0 {
			estimate = len(token) / 2
		}
		if reserved+estimate > MaxDecodedBytes {
			r.LimitReached = true
			break
		}
		reserved += estimate // Invalid candidates also consume the decoder budget.
		if hexToken(token) && len(token)%2 == 0 {
			kind = "hex"
			b, err = hex.DecodeString(token)
		} else {
			// One alphabet normalization, one decoding level. Removing legal
			// padding permits padded/unpadded standard and URL-safe forms.
			body := strings.TrimRight(token, "=")
			padding := len(token) - len(body)
			if padding > 2 || padding > 0 && (len(token)%4 != 0 || padding != (4-len(body)%4)%4) {
				continue
			}
			body = strings.NewReplacer("-", "+", "_", "/").Replace(body)
			b, err = base64.RawStdEncoding.Strict().DecodeString(body)
		}
		if err != nil {
			continue
		}
		if r.DecodedBytes+len(b) > MaxDecodedBytes {
			r.LimitReached = true
			break
		}
		r.DecodedBlobs++
		r.DecodedBytes += len(b)
		if !printable(b) {
			continue
		}
		decoded := string(b)
		if sourceMap(decoded) {
			r.Skipped++
			continue
		}
		r.TextBlobs++
		for _, typ := range hints(decoded) {
			found := false
			for j := range r.Findings {
				if r.Findings[j].Encoding == kind && r.Findings[j].Type == typ {
					r.Findings[j].Count++
					found = true
					break
				}
			}
			if !found {
				r.Findings = append(r.Findings, Finding{kind, typ, 1})
			}
		}
	}
	r.BytesScanned = i
	return r
}

func prefixFold(s, p string) bool { return len(s) >= len(p) && strings.EqualFold(s[:len(p)], p) }
func uriEnd(b byte) bool          { return b <= 32 || strings.ContainsRune("\"'`<>)]}", rune(b)) }
func tokenChar(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("+/=_-.", rune(b))
}
func alphabet(s string) bool {
	for i := range s {
		if !tokenChar(s[i]) || s[i] == '.' {
			return false
		}
	}
	return true
}
func identifier(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, b := range s {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_') {
			return false
		}
	}
	return true
}
func hexToken(s string) bool {
	for _, b := range s {
		if !(b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F' || b >= '0' && b <= '9') {
			return false
		}
	}
	return len(s) > 0
}
func knownToken(s string) bool {
	if strings.HasPrefix(s, "sha512-") || strings.HasPrefix(s, "sha256-") {
		return true
	}
	if (len(s) == 40 || len(s) == 64) && hexToken(s) {
		return true
	}
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' && hexToken(strings.ReplaceAll(s, "-", "")) {
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) == 3 {
		for _, p := range parts {
			if len(p) == 0 || !alphabet(p) || strings.ContainsAny(p, "+/=") {
				return false
			}
		}
		return true
	}
	return false
}
func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && !unicode.Is(unicode.Cf, r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
