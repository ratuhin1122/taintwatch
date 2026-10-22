package rules

import (
	"fmt"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

type Action string

const (
	Allow Action = "allow"
	Ask   Action = "ask"
	Deny  Action = "deny"
)

type Decision struct {
	Action         Action
	RuleID, Reason string
	Evidence       []string
}
type Policy struct {
	Secrets, ProtectedWrites, SelfPaths []string
	Overrides                           map[string]policy.Rule
	AllowedHosts                        []string
	StateHome                           string
	TrackedFiles                        []string
}

func DefaultPolicy() Policy {
	return FromPolicy(policy.Defaults())
}
func FromPolicy(c policy.Config) Policy {
	return Policy{AllowedHosts: append([]string{}, c.Egress.AllowDomains...), Secrets: append([]string{}, c.Secrets.Paths...), ProtectedWrites: append([]string{}, c.ProtectedWrites...), Overrides: c.Rules}
}

type Input struct {
	Policy                            Policy
	Session                           state.Session
	Tool, CWD, Command, FilePath, URL string
	Shell                             shellparse.Result
}

// Rule is the stable policy table; predicates inspect normalized facts, never JSON.
type Rule struct {
	ID, When string
	Action   Action
	Reason   string
	Match    func(Input) []string
}

var defaults = []Rule{
	{"TW006", "always", Ask, "this action changes Taintwatch enforcement or configuration", self},
	{"TW007", "always", Ask, "this command decodes or downloads content and executes it", decodeRun},
	{"TW001", "tainted", Ask, "this action accesses a secret path", secret},
	{"TW003", "tainted", Ask, "this command publishes code or changes a Git remote", publish},
	{"TW004", "tainted", Ask, "this command can destroy or overwrite data", destructive},
	{"TW005", "tainted", Ask, "this action writes protected configuration", protected},
	{"TW002", "tainted", Ask, "this action may send data to a host outside the allowlist", egress},
	{"TW008", "tainted", Ask, "shell analysis cannot resolve this command safely", uncertain},
}

// Defaults returns a copy so callers cannot mutate the built-in table.
func Defaults() []Rule { return append([]Rule(nil), defaults...) }
func Evaluate(in Input) Decision {
	chosen := Decision{Action: Allow, RuleID: "default.allow", Reason: "No applicable built-in risk rule matched."}
	matched := false
	rank := map[Action]int{Allow: 0, Ask: 1, Deny: 2}
	for _, r := range defaults {
		override, hasOverride := in.Policy.Overrides[r.ID]
		if hasOverride {
			if !override.Enabled {
				continue
			}
			r.Action = Action(override.Action)
		}
		if r.When == "tainted" && !in.Session.Tainted {
			continue
		}
		e := r.Match(in)
		if len(e) == 0 && hasOverride {
			facts := []string{in.Tool, in.Command, in.FilePath, in.URL}
			for _, pattern := range override.ExtraMatch {
				for _, v := range facts {
					if v != "" {
						if yes, _ := regexp.MatchString(pattern, v); yes {
							e = []string{"configured extra_match pattern"}
							break
						}
					}
				}
				if len(e) > 0 {
					break
				}
			}
		}
		if len(e) > 0 {
			reason := r.Reason + " (" + strings.Join(e, ", ") + ")."
			if in.Session.Tainted {
				cause := "an untrusted source"
				if len(in.Session.TaintEvents) > 0 {
					v := in.Session.TaintEvents[len(in.Session.TaintEvents)-1]
					cause = fmt.Sprintf("%s returned untrusted content at %s UTC", v.Tool, v.Time.UTC().Format("15:04"))
				}
				reason = "Session is tainted because " + cause + "; " + reason
			}
			if !matched || rank[r.Action] > rank[chosen.Action] {
				chosen = Decision{r.Action, r.ID, reason, e}
				matched = true
			}
		}
	}
	return chosen
}
func paths(in Input, write bool) []string {
	var ps []string
	if in.FilePath != "" {
		ps = append(ps, in.FilePath)
	}
	if write {
		ps = append(ps, in.Shell.Writes...)
	} else {
		ps = append(ps, in.Shell.Reads...)
	}
	return ps
}
func variants(in Input, p string) []string {
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.HasPrefix(p, "~/") {
		if h, e := os.UserHomeDir(); e == nil {
			p = h + p[1:]
		}
	}
	raw := p
	if !filepath.IsAbs(raw) && in.CWD != "" {
		raw = in.CWD + string(os.PathSeparator) + raw
	}
	out := []string{path.Clean(p), filepath.ToSlash(filepath.Clean(raw))}
	// Resolve the existing prefix before lexical cleaning, preserving symlink/.. order.
	probe := raw
	var tail []string
	for i := 0; i < 128; i++ {
		if v, e := filepath.EvalSymlinks(probe); e == nil {
			for j := len(tail) - 1; j >= 0; j-- {
				v = filepath.Join(v, tail[j])
			}
			out = append(out, filepath.ToSlash(v))
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		tail = append(tail, filepath.Base(probe))
		probe = parent
	}
	return out
}
func secret(in Input) []string {
	if in.Tool != "Read" && in.Tool != "Bash" {
		return nil
	}
	patterns := in.Policy.Secrets
	if patterns == nil {
		patterns = policy.Defaults().Secrets.Paths
	}
	for _, p := range paths(in, false) {
		for _, v := range variants(in, p) {
			for _, pattern := range patterns {
				if policy.MatchPath(pattern, v) {
					return []string{"secret path"}
				}
			}
		}
	}
	return nil
}
func contains(s string, ss ...string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}
func segment(s, p string) bool { return strings.Contains("/"+s+"/", "/"+p+"/") }
func writing(in Input) bool    { return in.Tool == "Write" || in.Tool == "Edit" || in.Tool == "Bash" }
func protected(in Input) []string {
	if !writing(in) {
		return nil
	}
	patterns := in.Policy.ProtectedWrites
	if patterns == nil {
		patterns = policy.Defaults().ProtectedWrites
	}
	for _, p := range paths(in, true) {
		for _, v := range variants(in, p) {
			for _, pattern := range patterns {
				if policy.MatchPath(pattern, v) {
					return []string{"protected path"}
				}
			}
		}
	}
	return nil
}
func self(in Input) []string {
	if writing(in) {
		for _, p := range paths(in, true) {
			for _, v := range variants(in, p) {
				for _, selfPath := range in.Policy.SelfPaths {
					for _, selfVariant := range variants(in, selfPath) {
						if filepath.Clean(v) == filepath.Clean(selfVariant) {
							return []string{"Taintwatch policy or audit path"}
						}
					}
				}
				l := strings.ToLower(v)
				if strings.HasSuffix(l, "/.taintwatch/policy.yaml") {
					return []string{"Taintwatch project policy"}
				}
				if (segment(l, "taintwatch") && (contains(path.Base(l), "policy.yaml", "policy.yml", "config.yaml", "config.yml") || segment(l, "sessions"))) || strings.Contains(path.Base(l), "taintwatch.") || strings.HasSuffix(l, "/hooks/hooks.json") || strings.HasSuffix(l, "/.claude/settings.json") || strings.HasSuffix(l, "/.claude/settings.local.json") || in.Policy.StateHome != "" && (l == strings.ToLower(filepath.ToSlash(in.Policy.StateHome)) || strings.HasPrefix(l, strings.ToLower(filepath.ToSlash(in.Policy.StateHome))+"/")) {
					return []string{"Taintwatch configuration or state"}
				}
			}
		}
	}
	for _, c := range in.Shell.Commands {
		if c.Name == "taintwatch" || c.Name == "taintwatch.exe" {
			if len(c.Args) >= 2 && c.Args[0] == "policy" && contains(c.Args[1], "check", "show") {
				continue
			}
			if len(c.Args) == 0 || !contains(c.Args[0], "version", "status", "explain", "--help", "-h") {
				return []string{"mutating taintwatch command"}
			}
		}
	}
	return nil
}
func publish(in Input) []string {
	for _, c := range in.Shell.Commands {
		a := nonflags(c.Args)
		if c.Name == "git" && (prefix(a, "push") || prefix(a, "remote", "add") || prefix(a, "remote", "set-url")) || c.Name == "gh" && (prefix(a, "pr", "create") || prefix(a, "release", "create")) {
			return []string{c.Name + " publication or remote mutation"}
		}
	}
	return nil
}
func nonflags(args []string) []string {
	var a []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			if contains(args[i], "-C", "-c", "--git-dir", "--work-tree", "--repo", "-R") {
				i++
			}
			continue
		}
		a = append(a, args[i])
	}
	return a
}
func prefix(a []string, ps ...string) bool {
	if len(a) < len(ps) {
		return false
	}
	for i, p := range ps {
		if a[i] != p {
			return false
		}
	}
	return true
}
func destructive(in Input) []string {
	for _, c := range in.Shell.Commands {
		a := strings.Join(c.Args, " ")
		words := nonflags(c.Args)
		bad := false
		switch c.Name {
		case "rm":
			recursive, force := false, false
			for _, v := range c.Args {
				if strings.HasPrefix(v, "-") {
					recursive = recursive || strings.Contains(v, "r") || v == "--recursive"
					force = force || strings.Contains(v, "f") || v == "--force"
				}
			}
			bad = recursive && force
		case "git":
			bad = prefix(words, "reset") && strings.Contains(a, "--hard") || prefix(words, "clean") && strings.Contains(a, "f") && strings.Contains(a, "d") || prefix(words, "push") && (strings.Contains(a, "--force") || strings.Contains(a, "-f"))
		case "dd":
			bad = true
		case "chmod":
			bad = strings.Contains(a, "777") && (strings.Contains(a, "-R") || strings.Contains(a, "--recursive"))
		case "truncate":
			for _, p := range c.Args {
				for _, t := range in.Policy.TrackedFiles {
					if path.Clean(p) == path.Clean(t) {
						bad = true
					}
				}
			}
			if len(in.Policy.TrackedFiles) == 0 {
				bad = true
			}
		}
		bad = bad || strings.HasPrefix(c.Name, "mkfs")
		upper := strings.ToUpper(strings.Join(strings.Fields(a), " "))
		bad = bad || strings.Contains(upper, "DROP TABLE") || strings.Contains(upper, "DROP DATABASE")
		if bad {
			return []string{"destructive " + c.Name + " operation"}
		}
	}
	return nil
}
func egress(in Input) []string {
	allowed := func(h string) bool {
		for _, a := range in.Policy.AllowedHosts {
			if strings.EqualFold(strings.TrimSuffix(a, "."), h) {
				return true
			}
		}
		return false
	}
	if in.Tool == "WebFetch" {
		h := shellparse.Host(in.URL)
		if h == "" || !allowed(h) {
			return []string{"destination " + safeHost(h)}
		}
	}
	for _, n := range in.Shell.Networks {
		if len(n.Hosts) == 0 || n.LowConfidence {
			return []string{n.Command + " with unresolved destination"}
		}
		for _, h := range n.Hosts {
			if !allowed(h) {
				return []string{"destination " + safeHost(h)}
			}
		}
	}
	return nil
}
func safeHost(h string) string {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "\r\n\t") {
		return "unknown"
	}
	return h
}
func uncertain(in Input) []string {
	if in.Tool == "Bash" && (in.Shell.Unparseable || in.Shell.Uncertain) {
		return []string{"unparseable or dynamic shell expansion"}
	}
	return nil
}
func decodeRun(in Input) []string {
	if in.Tool != "Bash" {
		return nil
	}
	decoder, shell, download, eval := false, false, false, false
	for _, c := range in.Shell.Commands {
		a := strings.Join(c.Args, " ")
		switch c.Name {
		case "base64":
			decoder = decoder || strings.Contains(a, "-d") || strings.Contains(a, "--decode")
		case "xxd":
			decoder = decoder || strings.Contains(a, "-r")
		case "curl", "wget":
			download = true
		case "sh", "bash", "zsh", "dash":
			shell = true
		case "eval":
			eval = true
		case "python", "python3", "node":
			l := strings.ToLower(a)
			if (strings.Contains(l, "base64") || strings.Contains(l, "fromhex") || strings.Contains(l, "buffer.from") || strings.Contains(l, "atob(")) && (strings.Contains(l, "exec") || strings.Contains(l, "eval") || strings.Contains(l, "spawn") || strings.Contains(l, "system")) {
				return []string{"interpreter decode and execution"}
			}
		}
	}
	if (decoder && (shell || eval || in.Shell.Uncertain) && (in.Shell.Pipelines > 0 || in.Shell.Substitutions > 0)) || (download && (shell || in.Shell.Uncertain) && in.Shell.Pipelines > 0) {
		return []string{"decoded or downloaded shell input"}
	}
	return nil
}
