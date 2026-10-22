package valuematch

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"html"
	"math/rand"
	"net/url"
	"strings"
	"testing"
)

func TestExtract(t *testing.T) {
	for _, tc := range []struct{ text, kind, want string }{
		{"Visit https://example.net/a?b=c.", "url", "https://example.net/a?b=c"},
		{"example.net", "host", "example.net"}, {"192.0.2.17", "ip", "192.0.2.17"},
		{"::1", "ip", "::1"}, {"::", "ip", "::"},
		{"[2001:db8::17]", "ip", "2001:db8::17"}, {"https://[2001:db8::1]/a", "ip", "2001:db8::1"},
		{"callback@hooks.example.net", "email", "callback@hooks.example.net"},
		{"open /tmp/collector.log", "path", "/tmp/collector.log"},
		{"build/report.log", "path", "build/report.log"}, {`C:\temp\collector.log`, "path", `C:\temp\collector.log`},
		{"../secrets/.env", "path", "../secrets/.env"}, {".env.local", "path", ".env.local"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			found := false
			for _, v := range Extract(tc.text) {
				if v.Text == tc.want && v.Kind == tc.kind {
					found = true
					if len(v.Variants) == 0 {
						t.Fatal("no variants")
					}
				}
			}
			if !found {
				t.Fatalf("missing %s: %+v", tc.want, Extract(tc.text))
			}
		})
	}
	if got := Extract("go test ./... runs tests. 普通中文 👩‍💻"); len(got) != 0 {
		t.Fatal(got)
	}
	if got := Extract(strings.Repeat("example.net ", 100)); len(got) != 1 {
		t.Fatal("dedup", len(got))
	}
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&b, "https://host%d.example/unique ", i)
	}
	if got := Extract(b.String()); len(got) != MaxValues {
		t.Fatal(len(got))
	}
	for _, v := range Extract("https://example.net/" + strings.Repeat("a", MaxValueBytes)) {
		if len(v.Text) > MaxValueBytes {
			t.Fatal("oversize token")
		}
	}
	if got := Extract(strings.Repeat(" ", MaxTextBytes) + "https://ignored.example/a"); len(got) != 0 {
		t.Fatal("scan cap")
	}
}

func TestEncodingsAndAlignments(t *testing.T) {
	for _, value := range []string{"https://hooks.example.net/collect?x=1&v=2", "/tmp/out.log", "192.0.2.77", "notify@webhook.example", "/tmp/ÿ🧪.log", ".env", "::1", "::"} {
		patterns := []Pattern{{Text: value, Source: "WebFetch"}}
		for _, v := range Variants(value) {
			patterns = append(patterns, Pattern{v, "WebFetch"})
		}
		m := Compile(patterns)
		for _, encoded := range []string{url.QueryEscape(value), url.PathEscape(value), hex.EncodeToString([]byte(value)), strings.ToUpper(hex.EncodeToString([]byte(value))), html.EscapeString(value)} {
			if _, ok := m.Match(encoded); !ok {
				t.Fatal("required encoding absent", encoded)
			}
		}
		for _, p := range patterns {
			if _, ok := m.Match("prefix" + p.Text + "suffix"); !ok {
				t.Fatal("variant", p.Text)
			}
		}
		for offset := 0; offset < 3; offset++ {
			for tail := 0; tail < 3; tail++ {
				payload := strings.Repeat("X", offset) + value + strings.Repeat("Z", tail)
				for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
					if _, ok := m.Match(enc.EncodeToString([]byte(payload))); !ok {
						t.Fatalf("alignment=%d tail=%d value=%s", offset, tail, value)
					}
				}
			}
		}
	}
	// Match outputs on failure links and overlapping suffixes are retained.
	m := Compile([]Pattern{{"abcdef", "first"}, {"bcde", "second"}, {"cdefghi", "third"}})
	if _, ok := m.Match("abcdeZ"); !ok {
		t.Fatal("failure output lost")
	}
	if _, ok := m.Match("unrelated"); ok {
		t.Fatal("near miss")
	}
}

func TestAllowedDomainOnly(t *testing.T) {
	for _, tc := range []struct {
		v    Value
		want bool
	}{
		{Value{Kind: "host", Text: "github.com"}, true},
		{Value{Kind: "ip", Text: "192.0.2.1"}, true},
		{Value{Kind: "url", Text: "https://github.com/"}, true},
		{Value{Kind: "url", Text: "https://github.com/attacker/path"}, false},
		{Value{Kind: "url", Text: "https://github.com/?token=x"}, false},
		{Value{Kind: "email", Text: "hook@github.com"}, false},
		{Value{Kind: "host", Text: "evilgithub.com"}, false},
	} {
		if got := DomainOnlyAllowed(tc.v, []string{"github.com", "192.0.2.1"}); got != tc.want {
			t.Fatal(tc.v, got)
		}
	}
}

func TestMatcherAgainstLiteralSearch(t *testing.T) {
	rng := rand.New(rand.NewSource(41))
	word := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = "abcd"[rng.Intn(4)]
		}
		return string(b)
	}
	for trial := 0; trial < 100; trial++ {
		patterns := []Pattern{}
		for i := 0; i < 32; i++ {
			patterns = append(patterns, Pattern{word(4 + rng.Intn(16)), "source"})
		}
		m := Compile(patterns)
		for i := 0; i < 100; i++ {
			text := word(64)
			want := false
			for _, p := range patterns {
				want = want || strings.Contains(text, p.Text)
			}
			if _, got := m.Match(text); got != want {
				t.Fatalf("automaton differs: %q", text)
			}
		}
	}
}

func FuzzExtractMatch(f *testing.F) {
	f.Add("https://example.net/hook", "prefixhttps://example.net/hook")
	f.Add("ordinary text", "")
	f.Fuzz(func(t *testing.T, text, arg string) {
		values := Extract(text)
		if len(values) > MaxValues {
			t.Fatal("count")
		}
		patterns := []Pattern{}
		for _, v := range values {
			if len(v.Text) > MaxValueBytes || len(v.Variants) > MaxVariants {
				t.Fatal("bounds")
			}
			patterns = append(patterns, Pattern{v.Text, "source"})
			for _, p := range v.Variants {
				patterns = append(patterns, Pattern{p, "source"})
			}
		}
		m := Compile(patterns)
		m.Match(arg)
		if len(m.nodes) > MaxPatternBytes+1 {
			t.Fatal("node budget")
		}
	})
}
