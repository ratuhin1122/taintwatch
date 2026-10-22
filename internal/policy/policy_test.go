package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func put(t *testing.T, p, body string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func setup(t *testing.T) (Options, string, string) {
	t.Helper()
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "")
	root := t.TempDir()
	user := filepath.Join(root, "home", ".config", "taintwatch", "policy.yaml")
	project := filepath.Join(root, "repo", ".taintwatch", "policy.yaml")
	cwd := filepath.Join(root, "repo", "src", "nested")
	if e := os.MkdirAll(cwd, 0700); e != nil {
		t.Fatal(e)
	}
	return Options{CWD: cwd, UserHome: filepath.Join(root, "home")}, user, project
}

func TestLayeringAndOrigins(t *testing.T) {
	opts, user, project := setup(t)
	put(t, user, "version: 1\nfail_mode: closed\nallow_project_loosening: true\negress:\n  allow_domains:\n    replace: [user.example]\nsecrets:\n  paths:\n    append: [user.secret]\n")
	put(t, project, "version: 1\nprofile: paranoid\negress:\n  allow_domains:\n    append: [project.example]\nrules:\n  TW001:\n    action: deny\n")
	e, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	if e.Config.FailMode != "closed" || e.Config.Profile != "paranoid" || strings.Join(e.Config.Egress.AllowDomains, ",") != "user.example,project.example" || !has(e.Config.Secrets.Paths, ".env*") || !has(e.Config.Secrets.Paths, "user.secret") || e.Config.Rules["TW001"].Action != "deny" || len(e.Files) != 2 {
		t.Fatalf("%+v", e)
	}
	if e.Origins["fail_mode"] != user+":2" || e.Origins["egress.allow_domains[0]"] != user+":6" || e.Origins["egress.allow_domains[1]"] != project+":5" {
		t.Fatalf("%+v", e.Origins)
	}
	var b bytes.Buffer
	if err = e.Show(&b); err != nil || !strings.Contains(b.String(), "origin: "+user) || !strings.Contains(b.String(), "origin: built-in") || !strings.Contains(b.String(), "project.example") {
		t.Fatalf("%s %v", b.String(), err)
	}
	if _, err = Parse(b.Bytes()); err != nil {
		t.Fatalf("shown effective policy is not valid input: %v\n%s", err, b.String())
	}
	// Only the nearest project policy is loaded, including when cwd is nested.
	nearest := filepath.Join(opts.CWD, ".taintwatch", "policy.yaml")
	put(t, nearest, "version: 1\nprofile: balanced\n")
	e, err = Load(opts)
	if err != nil || e.Config.Profile != "balanced" || e.Files[1] != nearest {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestHostileProjectCannotLoosen(t *testing.T) {
	opts, user, project := setup(t)
	put(t, user, "version: 1\nfail_mode: closed\nprofile: paranoid\negress:\n  allow_domains:\n    replace: [safe.example]\nsources:\n  mcp:\n    trusted_servers:\n      replace: [trusted]\nrules:\n  TW001:\n    action: deny\n")
	put(t, project, `version: 1
allow_project_loosening: true
fail_mode: open
profile: balanced
sources:
  tools: {replace: []}
  mcp:
    trusted_servers: {append: [attacker]}
  bash:
    reader_commands: {replace: []}
  read:
    taint_globs: {replace: []}
    temp_paths: {replace: []}
    downloaded_paths: {replace: []}
egress:
  allow_domains: {append: [evil.example]}
secrets:
  paths: {replace: []}
protected_writes: {replace: []}
rules:
  TW001: {enabled: false, action: allow, extra_match: {append: ['sensitive']}}
  TW006: {enabled: false}
  TW007: {action: allow}
log:
  path: /tmp/discard.log
  rotation: {max_bytes: 1, keep: 1}
state: {retention_days: 1}
`)
	e, err := Load(opts)
	if err != nil {
		t.Fatal(err)
	}
	c := e.Config
	if c.AllowProjectLoosening || c.FailMode != "closed" || c.Profile != "paranoid" || has(c.Egress.AllowDomains, "evil.example") || has(c.Sources.MCP.TrustedServers, "attacker") || !c.Rules["TW001"].Enabled || c.Rules["TW001"].Action != "deny" || !c.Rules["TW006"].Enabled || c.Rules["TW007"].Action != "ask" || c.Log.Path != "audit.jsonl" || c.Log.Rotation.Keep != 3 || c.Log.Rotation.MaxBytes != 10<<20 || c.State.RetentionDays != 7 || len(e.Ignored) < 10 {
		t.Fatalf("hostile project weakened config: %+v", e)
	}
	d := Defaults()
	if len(c.Secrets.Paths) != len(d.Secrets.Paths) || len(c.ProtectedWrites) != len(d.ProtectedWrites) || len(c.Sources.Tools) != len(d.Sources.Tools) || len(c.Sources.Read.TaintGlobs) != len(d.Sources.Read.TaintGlobs) || len(c.Sources.Bash.ReaderCommands) != len(d.Sources.Bash.ReaderCommands) {
		t.Fatal("lost restrictive list entries")
	}
	if !has(c.Rules["TW001"].ExtraMatch, "sensitive") {
		t.Fatal("restrictive extra pattern ignored")
	}
}

func TestProjectRestrictionsAndOptIn(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		t.Run(map[bool]string{false: "guarded", true: "opt-in"}[optIn], func(t *testing.T) {
			opts, user, project := setup(t)
			grant := "false"
			if optIn {
				grant = "true"
			}
			put(t, user, "version: 1\nallow_project_loosening: "+grant+"\n")
			put(t, project, "version: 1\nfail_mode: closed\nprofile: paranoid\nsources:\n  mcp:\n    trusted_servers: {append: [new]}\negress:\n  allow_domains: {append: [new.example]}\nsecrets:\n  paths: {append: [custom.secret]}\nrules:\n  TW006: {enabled: false}\n  TW001: {action: deny}\nstate: {retention_days: 14}\n")
			e, err := Load(opts)
			if err != nil {
				t.Fatal(err)
			}
			c := e.Config
			if c.FailMode != "closed" || c.Profile != "paranoid" || !has(c.Secrets.Paths, "custom.secret") || c.Rules["TW001"].Action != "deny" || c.State.RetentionDays != 14 {
				t.Fatal("restriction was rejected")
			}
			if has(c.Egress.AllowDomains, "new.example") != optIn || has(c.Sources.MCP.TrustedServers, "new") != optIn || c.Rules["TW006"].Enabled == optIn {
				t.Fatalf("opt-in mismatch: %+v", e)
			}
		})
	}
}

func TestValidation(t *testing.T) {
	cases := []struct{ yaml, want string }{
		{"version: 1\nfail_mdoe: closed\n", "line 2: unknown key \"fail_mdoe\" in policy; did you mean \"fail_mode\""},
		{"version: 1\nsources:\n  read:\n    taint_glbos: {append: []}\n", "line 4:"},
		{"version: 2", "unsupported version"}, {"profile: balanced", "version: 1 is missing"}, {"version: 1\nfail_mode: true", "single-line string"},
		{"version: 1\nprofile: other", "balanced or paranoid"}, {"version: 1\nfail_mode: nope", "open or closed"},
		{"version: 1\nallow_project_loosening: yes", "true or false"}, {"version: 1\nallow_project_loosening: null", "true or false"},
		{"version: 1\nversion: 1", "duplicate key"}, {"version: 1\n---\nversion: 1", "one YAML document"},
		{"version: [", "invalid YAML"}, {"[]", "mapping"}, {"version: 1\neg ress: {}", "unknown key"},
		{"version: 1\nsecrets: {paths: [a]}", "replace:"}, {"version: 1\nsecrets: {paths: {replace: [], append: []}}", "exactly one"},
		{"version: 1\nsecrets: {paths: {append: [null]}}", "nonempty"}, {"version: 1\nsecrets: {paths: {append: ['[']}}", "invalid glob"},
		{"version: 1\nrules: {TW999: {action: ask}}", "unknown key"}, {"version: 1\nrules: {TW001: {action: nope}}", "allow, ask or deny"},
		{"version: 1\nrules: {TW001: {enabled: 1}}", "true or false"}, {"version: 1\nrules: {TW001: {extra_match: {append: ['[']}}}", "invalid RE2"},
		{"version: 1\nsources: {bash: {reader_commands: {append: ['curl; wget']}}}", "literal command"},
		{"version: 1\negress: {allow_domains: {append: ['*.example.com']}}", "exact lowercase"},
		{"version: 1\negress: {allow_domains: {append: ['https://example.com']}}", "exact lowercase"},
		{"version: 1\nsources: {mcp: {trusted_servers: {append: ['*']}}}", "exact MCP"},
		{"version: 1\nstate: {retention_days: 0}", "positive decimal"}, {"version: 1\nstate: {retention_days: 3651}", "limit"},
		{"version: 1\nlog: {rotation: {keep: 21}}", "limit"}, {"version: 1\nlog: {path: ''}", "name a file"},
		{"version: 1\nsources: &x {}", "anchors"}, {"version: 1\nsources: !custom {}", "tags"},
	}
	for _, tc := range cases {
		t.Run(tc.yaml, func(t *testing.T) {
			_, e := Parse([]byte(tc.yaml))
			if e == nil || !strings.Contains(e.Error(), tc.want) {
				t.Fatalf("got %v want %q", e, tc.want)
			}
		})
	}
	if _, e := Parse(bytes.Repeat([]byte("x"), MaxBytes+1)); e == nil {
		t.Fatal("accepted oversized policy")
	}
}

func TestInvalidProjectReturnsLastValidPolicy(t *testing.T) {
	opts, user, project := setup(t)
	put(t, user, "version: 1\nfail_mode: closed\nprofile: paranoid\n")
	put(t, project, "version: 1\nunknown: true\n")
	e, err := Load(opts)
	if err == nil || e.Config.FailMode != "closed" || e.Config.Profile != "paranoid" {
		t.Fatalf("lost trusted fallback: %+v %v", e, err)
	}
}
func TestDefaultsIndependent(t *testing.T) {
	a, b := Defaults(), Defaults()
	a.Rules["TW001"] = Rule{}
	a.Secrets.Paths[0] = "changed"
	if b.Rules["TW001"].Action != "ask" || b.Secrets.Paths[0] != ".env*" {
		t.Fatal("shared mutable defaults")
	}
}

func TestProjectMayRemoveTrust(t *testing.T) {
	opts, user, project := setup(t)
	put(t, user, "version: 1\negress: {allow_domains: {replace: [keep.example, drop.example]}}\nsources: {mcp: {trusted_servers: {replace: [keep, drop]}}}\n")
	put(t, project, "version: 1\negress: {allow_domains: {replace: [keep.example]}}\nsources: {mcp: {trusted_servers: {replace: [keep]}}}\n")
	e, err := Load(opts)
	if err != nil || len(e.Ignored) != 0 || strings.Join(e.Config.Egress.AllowDomains, ",") != "keep.example" || strings.Join(e.Config.Sources.MCP.TrustedServers, ",") != "keep" {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestProjectCannotGrowAllowPatterns(t *testing.T) {
	opts, user, project := setup(t)
	put(t, user, "version: 1\nrules: {TW003: {action: allow, extra_match: {append: [existing]}}}\n")
	put(t, project, "version: 1\nrules: {TW003: {extra_match: {append: [new]}}}\n")
	e, err := Load(opts)
	if err != nil || has(e.Config.Rules["TW003"].ExtraMatch, "new") || !has(e.Config.Rules["TW003"].ExtraMatch, "existing") || len(e.Ignored) == 0 {
		t.Fatalf("%+v %v", e, err)
	}
}
func TestLegacyEnvironmentOrigins(t *testing.T) {
	opts, _, _ := setup(t)
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "2048")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "2")
	e, err := Load(opts)
	if err != nil || e.Config.Log.Rotation.MaxBytes != 2048 || e.Config.Log.Rotation.Keep != 2 || !strings.Contains(e.Origins["log.rotation.max_bytes"], "environment") {
		t.Fatalf("%+v %v", e, err)
	}
}
func FuzzPolicy(f *testing.F) {
	f.Add("version: 1\n")
	f.Add("version: 1\nsecrets: {paths: {append: ['*.pem']}}\n")
	f.Fuzz(func(t *testing.T, s string) { _, _ = Parse([]byte(s)) })
}
