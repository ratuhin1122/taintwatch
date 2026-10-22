package hidden

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxBytes bounds the UTF-8 prefix examined, independently of the hook input cap.
const MaxBytes = 1 << 20

// Finding aggregates one hint type; Excerpt is a small, visibly escaped sample,
// not the hidden body, link destination, or surrounding response contents.
type Finding struct {
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Excerpt string `json:"excerpt"`
}

// Report describes only the scanned prefix. Absence of findings proves no safety.
type Report struct {
	Findings     []Finding `json:"findings,omitempty"`
	BytesScanned int       `json:"bytes_scanned"`
	Truncated    bool      `json:"truncated"`
}

// Visible renders controls and concealment characters without emitting terminal
// escapes. It limits the input to 80 runes and output to less than 1 KiB.
func Visible(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == 80 {
			b.WriteString("…")
			break
		}
		n++
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Zl, r) || unicode.Is(unicode.Zp, r) || r >= 0xE0000 && r <= 0xE007F {
			fmt.Fprintf(&b, "<U+%04X>", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

var display = regexp.MustCompile(`(?i)\b(?:display\s*:\s*none|visibility\s*:\s*hidden)(?:\s*!important)?\s*(?:[;"'<>}]|$)`)
var tiny = regexp.MustCompile(`(?i)\bfont-size\s*:\s*(?:0(?:\.0+)?(?:px|pt|em|rem|%)?|0?\.\d+(?:px|pt)|[1-5](?:\.0+)?(?:px|pt)|0?\.[0-4]\d*(?:em|rem)|[1-5](?:\.\d+)?%)(?:\s*!important)?\s*(?:[;"'<>}]|$)`)
var styles = regexp.MustCompile(`(?i)\bstyle\s*=\s*(?:"[^"<>]*"|'[^'<>]*')`)
var colors = regexp.MustCompile(`(?i)\b(color|background-color|background)\s*:\s*(white|#fff(?:fff)?|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))\s*(?:!important\s*)?(?:;|$)`)

// Scan makes a fixed number of linear passes over at most MaxBytes. All regexes
// use Go's RE2 engine; custom parsers advance monotonically. Findings have fixed
// cardinality, even for a prefix consisting entirely of suspicious characters.
func Scan(text string) Report {
	r := Report{Truncated: len(text) > MaxBytes}
	if r.Truncated {
		n := MaxBytes
		for n > MaxBytes-utf8.UTFMax && !utf8.RuneStart(text[n]) {
			n--
		}
		text = text[:n]
	}
	r.BytesScanned = len(text)
	index := map[string]int{}
	add := func(kind, excerpt string) {
		if i, ok := index[kind]; ok {
			r.Findings[i].Count++
			return
		}
		index[kind] = len(r.Findings)
		r.Findings = append(r.Findings, Finding{kind, 1, Visible(excerpt)})
	}
	runes := []rune(text)
	start := -1
	word := func(end int) {
		if start < 0 {
			return
		}
		w := runes[start:end]
		latin, similar := 0, 0
		var glyphs [4]rune
		for _, c := range w {
			if unicode.In(c, unicode.Latin) {
				latin++
			}
			if strings.ContainsRune("ΑΒΕΖΗΙΚΜΝΟΡΤΥΧαεικνορτυχωАВЕКМНОРСТХаеорсухіјѕ", c) {
				similar++
				if similar <= len(glyphs) {
					glyphs[similar-1] = c
				}
			}
		}
		if latin > 0 && similar >= 2 && similar*3 >= len(w) {
			// Codepoints expose the confusable glyphs without recording a whole
			// word which could itself be a credential or private content.
			var sample strings.Builder
			for _, c := range glyphs {
				if c != 0 {
					fmt.Fprintf(&sample, "<U+%04X>", c)
				}
			}
			add("homoglyph", "…"+sample.String()+"…")
		}
		start = -1
	}
	flagEnd := -1
	for i, c := range runes {
		if c == 0x1F3F4 {
			flagEnd = subdivisionEnd(runes, i)
		}
		if unicode.IsLetter(c) {
			if start < 0 {
				start = i
			}
		} else {
			word(i)
		}
		switch {
		case c == 0x200B || c == 0x200C || c == 0x200D || c == 0x2060 || c == 0xFEFF:
			if c != 0x200D || !emojiJoin(runes, i) {
				add("zero-width", string(c))
			}
		case c >= 0x202A && c <= 0x202E || c >= 0x2066 && c <= 0x2069:
			add("bidi-control", string(c))
		case c >= 0xE0000 && c <= 0xE007F:
			if i > flagEnd {
				add("unicode-tag", string(c))
			}
		}
	}
	word(len(runes))
	for pos := 0; pos < len(text); {
		n := strings.Index(text[pos:], "<!--")
		if n < 0 {
			break
		}
		pos += n + 4
		add("html-comment", "<!-- … -->")
	}
	for _, m := range display.FindAllStringIndex(text, -1) {
		add("hidden-style", text[m[0]:m[1]])
	}
	for _, m := range tiny.FindAllStringIndex(text, -1) {
		add("small-font", text[m[0]:m[1]])
	}
	for _, m := range styles.FindAllString(text, -1) {
		value := m[strings.IndexByte(m, '=')+1:]
		value = strings.TrimSpace(value)
		value = value[1 : len(value)-1]
		if whitePair(value) {
			add("white-on-white", "color: white; background: white")
		}
	}
	// CSS declaration blocks, including stylesheets returned as plain text.
	for pos := 0; pos < len(text); {
		start := strings.IndexByte(text[pos:], '{')
		if start < 0 {
			break
		}
		start += pos + 1
		end := strings.IndexByte(text[start:], '}')
		if end < 0 {
			break
		}
		end += start
		if whitePair(text[start:end]) {
			add("white-on-white", "color: white; background: white")
		}
		pos = end + 1
	}
	links(text, add)
	return r
}

func whitePair(s string) bool {
	fg, bg := false, false
	for _, c := range colors.FindAllStringSubmatch(s, -1) {
		if strings.EqualFold(c[1], "color") {
			fg = true
		} else {
			bg = true
		}
	}
	return fg && bg
}

func pictograph(r rune) bool {
	return r >= 0x1F000 && r <= 0x1FAFF || r >= 0x2600 && r <= 0x27BF || r == 0xA9 || r == 0xAE || r == 0x203C || r == 0x2049 || r == 0x2122 || r == 0x2139 || r == 0x3030 || r == 0x303D || r == 0x3297 || r == 0x3299 || r >= 0x2194 && r <= 0x21FF || r >= 0x2300 && r <= 0x23FF || r >= 0x2B00 && r <= 0x2BFF
}
func emojiJoin(rs []rune, i int) bool {
	j := i - 1
	for j >= 0 && (rs[j] == 0xFE0F || rs[j] >= 0x1F3FB && rs[j] <= 0x1F3FF) {
		j--
	}
	return j >= 0 && i+1 < len(rs) && pictograph(rs[j]) && pictograph(rs[i+1])
}

// The three ordinary subdivision flag sequences use tag letters legitimately.
func subdivisionEnd(rs []rune, i int) int {
	if i+6 >= len(rs) || rs[i+6] != 0xE007F {
		return -1
	}
	var b [5]byte
	for j := 0; j < 5; j++ {
		c := rs[i+j+1]
		if c < 0xE0061 || c > 0xE007A {
			return -1
		}
		b[j] = byte(c - 0xE0000)
	}
	s := string(b[:])
	if s == "gbeng" || s == "gbsct" || s == "gbwls" {
		return i + 6
	}
	return -1
}

// links recognizes inline markdown links with balanced delimiters, escapes, and
// optional angle destinations. Each byte is visited a bounded number of times;
// malformed constructs are skipped without repeatedly scanning their suffix.
func links(s string, add func(string, string)) {
	labelStart, depth := -1, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == '[' {
			if depth == 0 {
				labelStart = i + 1
			}
			depth++
			continue
		}
		if s[i] != ']' || depth == 0 {
			continue
		}
		depth--
		if depth != 0 {
			continue
		}
		end := i
		if i+1 >= len(s) || s[i+1] != '(' {
			continue
		}
		i += 2
		destStart := i
		nest := 1
		for i < len(s) && nest > 0 {
			if s[i] == '\\' {
				i += 2
				continue
			}
			if s[i] == '(' {
				nest++
			}
			if s[i] == ')' {
				nest--
				if nest == 0 {
					break
				}
			}
			i++
		}
		if i >= len(s) {
			break
		}
		label := strings.TrimSpace(s[labelStart:end])
		dest := strings.TrimSpace(s[destStart:i])
		if fields := strings.Fields(dest); len(fields) > 0 {
			dest = fields[0]
		}
		dest = strings.Trim(dest, "<>")
		if label != "" && dest != "" && label != dest {
			add("markdown-link-mismatch", "[text](different target)")
		}
	}
}
