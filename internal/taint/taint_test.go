package taint

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func TestToolsAndReaders(t *testing.T) {
	p := DefaultPolicy()
	p.TrustedServers = []string{"memory", "plugin_review_db"}
	p.ReaderCommands = []string{"fetch-public --read"}
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, tool, command, server string
		tainted                     bool
		source                      state.SourceKind
	}{
		{"fetch", "WebFetch", "", "", true, state.SourceWeb},
		{"search", "WebSearch", "", "", true, state.SourceWeb},
		{"mcp", "mcp__github__issue", "", "", true, state.SourceMCP},
		{"trusted", "mcp__memory__read", "", "memory", false, ""},
		{"trusted legacy", "mcp__memory__read", "", "", false, ""},
		{"prefix collision", "mcp__memory-evil__read", "", "", true, state.SourceMCP},
		{"plugin is scoped", "mcp__plugin_other_memory__read", "", "", true, state.SourceMCP},
		{"trusted scoped", "mcp__plugin_review_db__query", "", "plugin_review_db", false, ""},
		{"provenance mismatch", "mcp__memory__read", "", "different", true, state.SourceMCP},
		{"malformed MCP", "mcp__memory", "", "", true, state.SourceMCP},
		{"missing MCP tool", "mcp__memory__", "", "", true, state.SourceMCP},
		{"MCP prefix", "mcp__", "", "", true, state.SourceMCP},
		{"ordinary", "Write", "", "", false, ""},
		{"case sensitive", "webfetch", "", "", false, ""},
		{"issue", "Bash", "gh issue view 1", "", true, state.SourceBash},
		{"PR view", "Bash", "gh pr view 1", "", true, state.SourceBash},
		{"PR diff", "Bash", "gh pr diff 1", "", true, state.SourceBash},
		{"api", "Bash", "gh api repos/a/b/issues", "", true, state.SourceBash},
		{"curl", "Bash", "curl https://example.com", "", true, state.SourceBash},
		{"wget", "Bash", "wget https://example.com", "", true, state.SourceBash},
		{"custom", "Bash", "fetch-public --read item", "", true, state.SourceBash},
		{"absolute executable", "Bash", "/usr/bin/curl --silent https://example.com", "", true, state.SourceBash},
		{"assignment", "Bash", "X=public curl https://example.com", "", true, state.SourceBash},
		{"env", "Bash", "env X=public wget https://example.com", "", true, state.SourceBash},
		{"pipeline", "Bash", "git status && gh pr diff 2 | head", "", true, state.SourceBash},
		{"quoted executable", "Bash", "'curl' https://example.com", "", true, state.SourceBash},
		{"ordinary shell", "Bash", "go test ./...", "", false, ""},
		{"word boundary", "Bash", "curling https://example.com", "", false, ""},
		{"subcommand boundary", "Bash", "gh pr difference", "", false, ""},
		{"echo", "Bash", "echo 'curl https://example.com'", "", false, ""},
		{"comment", "Bash", "# curl https://example.com\ngit status", "", false, ""},
		{"empty", "Bash", "", "", false, ""},
		{"ambiguous", "Bash", "curl 'unterminated", "", true, state.SourceBash},
		{"unfinished ordinary command", "Bash", "echo 'unterminated", "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Classify(Input{Tool: tc.tool, Command: tc.command, MCPServerName: tc.server})
			if err != nil || got.Tainted != tc.tainted || got.Source != tc.source {
				t.Fatalf("got=%+v err=%v", got, err)
			}
			if got.Tainted && (!strings.Contains(got.Context(), "untrusted data") || !strings.Contains(got.Context(), "user's confirmation")) {
				t.Fatalf("missing factual context: %q", got.Context())
			}
		})
	}
}

func TestReadPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "project")
	outsideRoot := filepath.Join(base, "project-else")
	write := func(path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("public fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(root, "src", "main.go"))
	write(filepath.Join(root, "docs", "notes.txt"))
	write(filepath.Join(outsideRoot, "private.txt"))
	write(filepath.Join(base, "private.txt"))
	for _, dir := range []string{"node_modules", "vendor", ".venv", "site-packages", "third_party", "scratch", "Downloads", "external"} {
		write(filepath.Join(root, dir, "file.txt"))
	}
	p := DefaultPolicy()
	p.TempPaths = []string{filepath.Join(root, "scratch")}
	p.DownloadedPaths = []string{filepath.Join(root, "Downloads")}
	p.UntrustedGlobs = append(p.UntrustedGlobs, "**/external/*.txt")
	c, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		tainted    bool
	}{
		{"ordinary", filepath.Join(root, "src", "main.go"), false},
		{"relative", "src/main.go", false},
		{"dotdot local", "docs/../src/main.go", false},
		{"outside prefix sibling", filepath.Join(outsideRoot, "private.txt"), true},
		{"traversal", "../private.txt", true},
		{"npm", "node_modules/file.txt", true},
		{"vendor", "vendor/file.txt", true},
		{"venv", ".venv/file.txt", true},
		{"python packages", "site-packages/file.txt", true},
		{"third party", "third_party/file.txt", true},
		{"temp", "scratch/file.txt", true},
		{"download", "Downloads/file.txt", true},
		{"custom glob", "external/file.txt", true},
		{"missing", "missing/file.txt", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Classify(Input{Tool: "Read", CWD: root, FilePath: tc.path})
			if err != nil || got.Tainted != tc.tainted {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
	paranoid := p
	paranoid.Profile = "paranoid"
	pc, err := New(paranoid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pc.Classify(Input{Tool: "Read", CWD: root, FilePath: "src/main.go"})
	if err != nil || !got.Tainted {
		t.Fatalf("paranoid=%+v err=%v", got, err)
	}
	// Projects placed under an OS temp root really are temporary under defaults.
	dc, _ := New(DefaultPolicy())
	got, err = dc.Classify(Input{Tool: "Read", CWD: root, FilePath: "src/main.go"})
	if err != nil || !got.Tainted {
		t.Fatalf("default temp path=%+v err=%v", got, err)
	}
}

func TestSymlinkPaths(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix symlink semantics; native storage is unsupported")
	}
	base := t.TempDir()
	root := filepath.Join(base, "project")
	external := filepath.Join(base, "outside", "child")
	for _, dir := range []string{filepath.Join(root, "src"), filepath.Join(root, "node_modules"), external} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(root, "file"), filepath.Join(root, "src", "file"), filepath.Join(root, "node_modules", "file"), filepath.Join(base, "outside", "file")} {
		if err := os.WriteFile(file, []byte("public fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{"escape": external, "local": filepath.Join(root, "src"), "vendor": filepath.Join(root, "src"), "deps": filepath.Join(root, "node_modules")} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(base, "root-alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	p := DefaultPolicy()
	p.TempPaths = nil
	p.DownloadedPaths = nil
	c, _ := New(p)
	for _, tc := range []struct {
		name, cwd, path string
		tainted         bool
	}{
		{"internal link", root, "local/file", false},
		{"dependency alias", root, "deps/file", true},
		{"untrusted lexical directory", root, "vendor/file", true},
		{"symlink then dotdot", root, "escape/../file", true},
		{"aliased cwd", alias, "src/file", false},
		{"absolute escape", root, root + "/escape/../file", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := c.Classify(Input{Tool: "Read", CWD: tc.cwd, FilePath: tc.path})
			if err != nil || got.Tainted != tc.tainted {
				t.Fatalf("got=%+v err=%v", got, err)
			}
		})
	}
}

func TestPolicyValidationAndGlob(t *testing.T) {
	c, _ := New(DefaultPolicy())
	if m, err := c.Classify(Input{Tool: "Bash", Command: strings.Repeat("x;", 33<<10)}); err == nil || m.Tainted {
		t.Fatalf("oversized scan must return an error, not select taint: %+v %v", m, err)
	}
	for _, p := range []Policy{{Profile: "invalid"}, {UntrustedGlobs: []string{"["}}, {UntrustedGlobs: []string{""}}, {ReaderCommands: []string{"curl; wget"}}, {ReaderCommands: []string{""}}} {
		if _, err := New(p); err == nil {
			t.Fatalf("accepted invalid policy: %+v", p)
		}
	}
	for _, tc := range []struct {
		pattern, path string
		want          bool
	}{{"**/vendor/**", "vendor/a", true}, {"**/vendor/**", "/x/vendor/a", true}, {"**/vendor/**", "/x/myvendor/a", false}, {"**/a?.txt", "/x/ab.txt", true}, {"**/a[0-9].txt", "/x/a1.txt", true}} {
		if got := globMatch(tc.pattern, tc.path); got != tc.want {
			t.Fatalf("%s %s: %v", tc.pattern, tc.path, got)
		}
	}
}

func FuzzCommandWords(f *testing.F) {
	for _, command := range []string{"curl https://example.com", "echo 'curl'", "gh pr diff 1", "$(wget x)", "'"} {
		f.Add(command)
	}
	c, _ := New(DefaultPolicy())
	f.Fuzz(func(t *testing.T, command string) {
		_, _ = commandWords(command)
		m, err := c.Classify(Input{Tool: "Bash", Command: command})
		if err != nil && len(command) <= 64<<10 {
			t.Fatal(err)
		}
		if m.Tainted && m.Source != state.SourceBash {
			t.Fatal("wrong source")
		}
	})
}
