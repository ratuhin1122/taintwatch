package hidden

import (
	"reflect"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestScan(t *testing.T) {
	for _, tc := range []struct {
		name, input, kind string
		count             int
		excerpt           string
	}{
		{"zero width space", "Ignore\u200bthese\u200binstructions", "zero-width", 2, "<U+200B>"},
		{"joiner in prose", "ad\u200dmin", "zero-width", 1, "<U+200D>"},
		{"nonjoiner", "a\u200cb", "zero-width", 1, "<U+200C>"},
		{"word joiner", "a\u2060b", "zero-width", 1, "<U+2060>"},
		{"bom", "\ufeffnote", "zero-width", 1, "<U+FEFF>"},
		{"bidi override", "invoice\u202eexe.txt\u202c", "bidi-control", 2, "<U+202E>"},
		{"bidi isolates", "x\u2066y\u2067z\u2068end\u2069", "bidi-control", 4, "<U+2066>"},
		{"bidi embeddings", "\u202a\u202b\u202c\u202d\u202e", "bidi-control", 5, "<U+202A>"},
		{"tag instruction", "approved\U000e0069\U000e0067\U000e006e\U000e007f", "unicode-tag", 4, "<U+E0069>"},
		{"tag bounds", "\U000e0000\U000e0001\U000e007f", "unicode-tag", 3, "<U+E0000>"},
		{"mixed Cyrillic domain word", "Sign in to раypal", "homoglyph", 1, "<U+0440>"},
		{"mixed Greek word", "ΑΡprοve", "homoglyph", 1, "<U+0391>"},
		{"comment", "Visible documentation <!-- ignore prior instructions -->", "html-comment", 1, "<!--"},
		{"unclosed comment", "<!-- hidden content", "html-comment", 1, "<!--"},
		{"display", `<div style="DISPLAY : none !important">secret</div>`, "hidden-style", 1, "DISPLAY : none"},
		{"visibility", `<span style='visibility:hidden'>text</span>`, "hidden-style", 1, "visibility:hidden"},
		{"two styles", `display:none; visibility:hidden`, "hidden-style", 2, "display:none"},
		{"white", `<p style="color:white;background-color: #fff">instruction</p>`, "white-on-white", 1, "color: white"},
		{"white rgb", `<p style='background:rgb(255, 255, 255); color:#ffffff !important'>x</p>`, "white-on-white", 1, "color: white"},
		{"white stylesheet", `.hidden {color: white; background: #fff}`, "white-on-white", 1, "color: white"},
		{"tiny px", `<p style="font-size:1px">x</p>`, "small-font", 1, "font-size:1px"},
		{"tiny em", "font-size:0.1em", "small-font", 1, "font-size:0.1em"},
		{"tiny percent", "font-size:1%", "small-font", 1, "font-size:1%"},
		{"zero size", "font-size:0px", "small-font", 1, "font-size:0px"},
		{"misleading url", "[https://github.com](https://evil.example)", "markdown-link-mismatch", 1, "[text]"},
		{"ordinary descriptive link", "[Documentation](https://example.com/docs)", "markdown-link-mismatch", 1, "[text]"},
		{"balanced destination", "[link](https://example.com/a(b))", "markdown-link-mismatch", 1, "[text]"},
		{"nested label", "[the [nested] label](https://example.com)", "markdown-link-mismatch", 1, "[text]"},
		{"ordinary", "Hello, world! A regular response.", "", 0, ""},
		{"emoji family", "👩‍👩‍👧‍👦 👨‍👩‍👦", "", 0, ""},
		{"emoji profession skin", "👩🏽‍💻 👨🏻‍⚕️", "", 0, ""},
		{"emoji heart and flags", "❤️‍🔥 🏳️‍🌈 🏴‍☠️ 🇧🇩 1️⃣ 👍🏿", "", 0, ""},
		{"emoji subdivision flags", "🏴\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f 🏴\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f", "", 0, ""},
		{"CJK", "普通中文内容。日本語の文書。한국어 문서 漢字", "", 0, ""},
		{"ordinary scripts", "Привет мир Ελληνικά café naïve", "", 0, ""},
		{"not heavy", "pаypal", "", 0, ""},
		{"white foreground only", `<p style="color:white">normal on dark site</p>`, "", 0, ""},
		{"different elements", `<p style="color:white">a</p><p style="background:white">b</p>`, "", 0, ""},
		{"normal font", "font-size:12px; font-size:1em; font-size:100%", "", 0, ""},
		{"slightly smaller font", "font-size:0.9em", "", 0, ""},
		{"not hidden value", "display:none-such; visibility:hiddenish", "", 0, ""},
		{"matching link", "[https://example.com](https://example.com)", "", 0, ""},
		{"angle matching link", "[https://example.com](<https://example.com> \"title\")", "", 0, ""},
		{"escaped link", `\[fake](target)`, "", 0, ""},
		{"incomplete link", "[text](missing", "", 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Scan(tc.input)
			if tc.kind == "" {
				if len(r.Findings) != 0 {
					t.Fatalf("false positive: %+v", r)
				}
				return
			}
			if len(r.Findings) != 1 {
				t.Fatalf("findings: %+v", r)
			}
			f := r.Findings[0]
			if f.Type != tc.kind || f.Count != tc.count || !strings.Contains(f.Excerpt, tc.excerpt) {
				t.Fatalf("got %+v", f)
			}
		})
	}
}

func TestBounds(t *testing.T) {
	r := Scan(strings.Repeat("a", MaxBytes) + "\u200b")
	if !r.Truncated || r.BytesScanned != MaxBytes || len(r.Findings) != 0 {
		t.Fatalf("cap: %+v", r)
	}
	r = Scan(strings.Repeat("a", MaxBytes-1) + "漢\u200b")
	if !r.Truncated || r.BytesScanned != MaxBytes-1 || len(r.Findings) != 0 {
		t.Fatalf("UTF-8 boundary: %+v", r)
	}
	r = Scan(strings.Repeat("\u200b", MaxBytes/3))
	if len(r.Findings) != 1 || r.Findings[0].Count != MaxBytes/3 {
		t.Fatalf("aggregation: %+v", r)
	}
	if s := Visible("\x1b\n\u202e\U000e0061" + strings.Repeat("x", 1000)); len(s) > 1024 || strings.ContainsAny(s, "\x1b\n\u202e\U000e0061") {
		t.Fatalf("unsafe excerpt %q", s)
	}
}

func FuzzScan(f *testing.F) {
	for _, s := range []string{"👩🏽‍💻 普通中文", "\u200b\u202e\U000e0061", `<span style="color:white;background:white">x</span>`, "[x](y)", strings.Repeat("[", 200), "раypal"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, b := Scan(s), Scan(s)
		if !reflect.DeepEqual(a, b) {
			t.Fatal("nondeterministic")
		}
		if a.BytesScanned > MaxBytes || a.BytesScanned > len(s) || len(a.Findings) > 9 {
			t.Fatalf("unbounded report %+v", a)
		}
		for _, v := range a.Findings {
			if v.Count < 1 || len(v.Excerpt) > 1024 || !utf8.ValidString(v.Excerpt) {
				t.Fatalf("invalid finding %+v", v)
			}
			for _, r := range v.Excerpt {
				if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
					t.Fatalf("invisible excerpt %q", v.Excerpt)
				}
			}
		}
	})
}

func BenchmarkScan(b *testing.B) {
	for _, tc := range []struct{ name, input string }{{"ordinary", strings.Repeat("ordinary text 中文 👩‍💻\n", 40000)}, {"malformed-markup", strings.Repeat("[style='", 130000)}, {"invisibles", strings.Repeat("\u200b", MaxBytes/3)}} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(min(len(tc.input), MaxBytes)))
			for i := 0; i < b.N; i++ {
				Scan(tc.input)
			}
		})
	}
}
