package shellparse

import "testing"

func TestStructure(t *testing.T) {
	r := Parse("(cat < input | grep x) && echo $(head data); cat <<'EOF' > output\nhello\nEOF\n")
	if r.Unparseable || r.Pipelines != 1 || r.Subshells != 1 || r.Substitutions != 1 || r.Heredocs != 1 || len(r.Commands) != 5 || len(r.Reads) < 2 || len(r.Writes) != 1 {
		t.Fatalf("%+v", r)
	}
}
func TestLiterals(t *testing.T) {
	for _, s := range []string{"cu'rl' https://example.com", "cu\\rl https://example.com", "\"curl\" https://example.com", "$'cu\\x72l' https://example.com", "$'cu\\162l' https://example.com"} {
		r := Parse(s)
		if r.Unparseable || len(r.Commands) != 1 || r.Commands[0].Name != "curl" {
			t.Fatalf("%s: %+v", s, r)
		}
	}
}
func TestHost(t *testing.T) {
	for s, w := range map[string]string{"https://user:pass@Example.com:443/x": "example.com", "git@github.com:owner/repo": "github.com", "user@example.com:/x": "example.com", "https://github.com.evil/x": "github.com.evil"} {
		if g := Host(s); g != w {
			t.Fatalf("%q: %q != %q", s, g, w)
		}
	}
}
func FuzzParse(f *testing.F) {
	for _, s := range []string{"echo ok", "cat < .env", "$(curl x)", "`wget x`", "cat <<EOF\na\nEOF", "'", "eval \"$(base64 -d x)\""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := Parse(s)
		if r.Unparseable && !r.Uncertain {
			t.Fatal("failure must be conservative")
		}
	})
}
