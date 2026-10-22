package policy

import (
	"os"
	"path"
	"regexp"
	"strings"
)

type Config struct {
	Version               int     `yaml:"version"`
	FailMode              string  `yaml:"fail_mode"`
	Profile               string  `yaml:"profile"`
	AllowProjectLoosening bool    `yaml:"allow_project_loosening"`
	Sources               Sources `yaml:"sources"`
	Egress                struct {
		AllowDomains []string `yaml:"allow_domains"`
	} `yaml:"egress"`
	Secrets struct {
		Paths      []string `yaml:"paths"`
		AllowPaths []string `yaml:"allow_paths"`
	} `yaml:"secrets"`
	ProtectedWrites []string        `yaml:"protected_writes"`
	Rules           map[string]Rule `yaml:"rules"`
	Log             struct {
		Path     string `yaml:"path"`
		Rotation struct {
			MaxBytes int64 `yaml:"max_bytes"`
			Keep     int   `yaml:"keep"`
		} `yaml:"rotation"`
	} `yaml:"log"`
	State struct {
		RetentionDays int `yaml:"retention_days"`
	} `yaml:"state"`
}
type Sources struct {
	Tools []string `yaml:"tools"`
	MCP   struct {
		TrustedServers []string `yaml:"trusted_servers"`
	} `yaml:"mcp"`
	Bash struct {
		ReaderCommands []string `yaml:"reader_commands"`
	} `yaml:"bash"`
	Read struct {
		TaintGlobs      []string `yaml:"taint_globs"`
		TempPaths       []string `yaml:"temp_paths"`
		DownloadedPaths []string `yaml:"downloaded_paths"`
	} `yaml:"read"`
}
type Rule struct {
	Action     string           `yaml:"action"`
	Enabled    bool             `yaml:"enabled"`
	ExtraMatch []string         `yaml:"extra_match"`
	Compiled   []*regexp.Regexp `yaml:"-" json:"-"`
}

var RuleIDs = []string{"TW001", "TW002", "TW003", "TW004", "TW005", "TW006", "TW007", "TW008", "TW009"}

// Defaults is the single source of production policy defaults. It owns all slices.
func Defaults() Config {
	var c Config
	c.Version = 1
	c.FailMode = "open"
	c.Profile = "balanced"
	c.Sources.Tools = []string{"WebFetch", "WebSearch", "mcp__*", "Bash", "Read"}
	c.Sources.MCP.TrustedServers = []string{}
	c.Sources.Bash.ReaderCommands = []string{"gh issue view", "gh pr view", "gh pr diff", "gh api", "curl", "wget"}
	c.Sources.Read.TaintGlobs = []string{"**/node_modules/**", "**/vendor/**", "**/.venv/**", "**/site-packages/**", "**/third_party/**"}
	c.Sources.Read.TempPaths = []string{os.TempDir(), "/tmp", "/var/tmp"}
	c.Sources.Read.DownloadedPaths = []string{}
	if h, e := os.UserHomeDir(); e == nil {
		c.Sources.Read.DownloadedPaths = []string{h + string(os.PathSeparator) + "Downloads"}
	}
	c.Egress.AllowDomains = strings.Fields("github.com api.github.com raw.githubusercontent.com objects.githubusercontent.com registry.npmjs.org pypi.org files.pythonhosted.org proxy.golang.org sum.golang.org")
	c.Secrets.Paths = []string{".env*", "*.pem", "*.key", "**/.ssh/**", "**/.aws/**", "**/.config/gcloud/**", "**/.kube/config", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "id_rsa*", "**/.docker/config.json", "*.tfstate", "*_history", ".history"}
	c.Secrets.AllowPaths = []string{}
	c.ProtectedWrites = []string{"**/.claude/**", ".mcp.json", "CLAUDE.md", "**/.github/workflows/**", "**/.git/hooks/**", ".bashrc", ".bash_profile", ".profile", ".zshrc", ".zprofile", "package.json", "**/.ssh/**", "**/.aws/**"}
	c.Rules = map[string]Rule{}
	for _, id := range RuleIDs {
		c.Rules[id] = Rule{Action: "ask", Enabled: true, ExtraMatch: []string{}}
	}
	c.Log.Path = "audit.jsonl"
	c.Log.Rotation.MaxBytes = 10 << 20
	c.Log.Rotation.Keep = 3
	c.State.RetentionDays = 7
	return c
}

// MatchPath implements slash-separated globs with ** spanning zero or more
// segments. A pattern without slashes matches any basename. No filesystem reads.
func MatchPath(pattern, value string) bool {
	value = strings.ReplaceAll(value, "\\", "/")
	pattern = strings.ReplaceAll(pattern, "\\", "/")
	if !strings.Contains(pattern, "/") {
		ok, _ := path.Match(pattern, path.Base(value))
		return ok
	}
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	vs := strings.Split(strings.Trim(value, "/"), "/")
	row := make([]bool, len(vs)+1)
	row[0] = true
	for _, p := range ps {
		next := make([]bool, len(vs)+1)
		for i := 0; i <= len(vs); i++ {
			if p == "**" {
				next[i] = row[i] || i > 0 && next[i-1]
			} else if i > 0 && row[i-1] {
				next[i], _ = path.Match(p, vs[i-1])
			}
		}
		row = next
	}
	return row[len(vs)]
}
