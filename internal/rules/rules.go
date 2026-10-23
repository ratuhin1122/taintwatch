package rules

import (
	"fmt"
	"github.com/ratuhin1122/taintwatch/internal/detect/decoderun"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"os"
	"path"
	"path/filepath"
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
	AllowedPaths                        []string
	Overrides                           map[string]policy.Rule
	AllowedHosts                        []string
	StateHome                           string
	TrackedFiles                        []string
}

func DefaultPolicy() Policy {
	return FromPolicy(policy.Defaults())
}
func FromPolicy(c policy.Config) Policy {
	return Policy{AllowedHosts: append([]string{}, c.Egress.AllowDomains...), AllowedPaths: append([]string{}, c.Secrets.AllowPaths...), Secrets: append([]string{}, c.Secrets.Paths...), ProtectedWrites: append([]string{}, c.ProtectedWrites...), Overrides: c.Rules}
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
	{"TW007", "always", Ask, "This command decodes data and executes it", decodeRun},
	{"TW001", "tainted", Ask, "this action accesses a secret path", secret},
	{"TW003", "tainted", Ask, "this command publishes code or changes a Git remote", publish},
	{"TW004", "tainted", Ask, "this command can destroy or overwrite data", destructive},
	{"TW005", "tainted", Ask, "this action writes protected configuration", protected},
	{"TW002", "tainted", Ask, "this action may send data to a host outside the allowlist", egress},
	{"TW008", "tainted", Ask, "shell analysis cannot resolve this command safely", uncertain},
	{"TW009", "tainted", Ask, "This argument came from untrusted content read earlier", valueMatch},
}

// Defaults returns a copy so callers cannot mutate the built-in table.
func Defaults() []Rule { return append([]Rule(nil), defaults...) }
func Evaluate(in Input) Decision {
	d, _ := evaluate(in, false, true)
	return d
}

// EvaluateTraced records every matching rule, including disabled rules, without
// retaining commands, paths, URLs, response contents, or predicate evidence.
func EvaluateTraced(in Input) (Decision, Snapshot) { return evaluate(in, true, true) }

// EvaluateEssential excludes supplemental regex until session state is known.
func EvaluateEssential(in Input) Decision { d, _ := evaluate(in, false, false); return d }

func evaluate(in Input, capture, extras bool) (Decision, Snapshot) {
	snapshot := Snapshot{Version: matchSchemaVersion, Matches: []string{}}
	chosen := Decision{Action: Allow, RuleID: "default.allow", Reason: "No applicable built-in risk rule matched."}
	matched := false
	chosenIndex := len(defaults)
	seenMatches := map[string]bool{}
	valueReason := ""
	rank := map[Action]int{Allow: 0, Ask: 1, Deny: 2}
	// Complete essential predicates before considering repository-supplied regex.
	for pass := 0; pass < 2; pass++ {
		if pass == 1 && !extras {
			break
		}
		budget := 16
		for index, r := range defaults {
			override, hasOverride := in.Policy.Overrides[r.ID]
			enabled := !hasOverride || override.Enabled
			if !capture && !enabled {
				continue
			}
			if hasOverride {
				r.Action = Action(override.Action)
			}
			if r.When == "tainted" && !in.Session.Tainted {
				continue
			}
			var e []string
			if pass == 0 {
				e = r.Match(in)
			}
			if pass == 1 && hasOverride {
				facts := []string{in.Tool, in.Command, in.FilePath, in.URL}
				for _, pattern := range override.Compiled {
					if budget == 0 {
						snapshot.Version = 0 // incomplete match facts cannot be replayed
						e = []string{"configured regex budget exhausted"}
						r.Action = Ask
						break
					}
					budget--
					for _, v := range facts {
						if len(v) > 64 {
							v = v[:64]
						}
						if v != "" {
							if pattern.MatchString(v) {
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
				if capture && !seenMatches[r.ID] {
					snapshot.Matches = append(snapshot.Matches, r.ID)
					seenMatches[r.ID] = true
				}
				if !enabled {
					continue
				}
				if r.ID == "TW009" {
					r.Reason += " (" + e[0] + ")"
					if r.Action == Ask {
						valueReason = r.Reason + "."
					}
					e = []string{"exact or encoded provenance indicator matched; value omitted"}
				}
				if r.ID == "TW007" && e[0] == "downloaded input reaches executable code" {
					r.Reason = "This command downloads data and executes it"
				}
				reason := r.Reason + " (" + strings.Join(e, ", ") + ")."
				if in.Session.Tainted {
					cause := "an untrusted source"
					if len(in.Session.TaintEvents) > 0 {
						v := in.Session.TaintEvents[len(in.Session.TaintEvents)-1]
						cause = fmt.Sprintf("%s returned untrusted content at %s UTC", v.Tool, v.Time.UTC().Format("15:04"))
					}
					reason = "Session is tainted because " + cause + "; " + reason
				}
				if !matched || rank[r.Action] > rank[chosen.Action] || rank[r.Action] == rank[chosen.Action] && index < chosenIndex {
					chosen = Decision{r.Action, r.ID, reason, e}
					chosenIndex = index
					matched = true
				}
			}
		}
	}
	if valueReason != "" && chosen.Action == Ask && chosen.RuleID != "TW009" {
		chosen.Reason += " " + valueReason
	}
	return chosen, snapshot
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
	if in.Tool == "Bash" {
		cwd := in.CWD
		originals := append([]string{}, ps...)
		for _, c := range in.Shell.Commands {
			if c.Name == "cd" && len(c.Args) == 1 && !c.Dynamic {
				if filepath.IsAbs(c.Args[0]) {
					cwd = c.Args[0]
				} else {
					cwd = filepath.Join(cwd, c.Args[0])
				}
				// Retain both possibilities for conditional/subshell cd. This
				// is conservative static analysis, not shell execution.
				for _, p := range originals {
					if !filepath.IsAbs(p) {
						ps = append(ps, filepath.Join(cwd, p))
					}
				}
			}
		}
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
		// Require the actual resolved file to match the approved canonical name.
		// Missing/unresolvable files and symlinks retargeted later get no exception.
		raw := p
		if !filepath.IsAbs(raw) {
			raw = in.CWD + string(os.PathSeparator) + raw
		}
		resolved, err := filepath.EvalSymlinks(raw)
		allowed := false
		if err == nil {
			for _, approved := range in.Policy.AllowedPaths {
				if filepath.Clean(resolved) == approved {
					allowed = true
					break
				}
			}
		}
		if allowed {
			continue
		}
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
				if (segment(l, "taintwatch") && (contains(path.Base(l), "policy.yaml", "policy.yml", "config.yaml", "config.yml") || segment(l, "sessions"))) || (path.Base(l) == "taintwatch" || strings.HasPrefix(path.Base(l), "taintwatch-") || strings.Contains(path.Base(l), "taintwatch.")) || strings.HasSuffix(l, "/hooks/hooks.json") || strings.HasSuffix(l, "/.claude/settings.json") || strings.HasSuffix(l, "/.claude/settings.local.json") || in.Policy.StateHome != "" && (l == strings.ToLower(filepath.ToSlash(in.Policy.StateHome)) || strings.HasPrefix(l, strings.ToLower(filepath.ToSlash(in.Policy.StateHome))+"/")) {
					return []string{"Taintwatch configuration or state"}
				}
			}
		}
	}
	for _, c := range in.Shell.Commands {
		// Argument signatures survive copying or renaming the executable.
		if len(c.Args) >= 3 && contains(c.Args[0], "allow", "disallow") && contains(c.Args[1], "domain", "path") || len(c.Args) >= 2 && c.Args[0] == "clear" && strings.HasPrefix(c.Args[1], "--reason") {
			return []string{"mutating taintwatch argument signature"}
		}
		if c.Name == "sh" || c.Name == "bash" || c.Name == "dash" || c.Name == "zsh" {
			a := nonflags(c.Args)
			if len(a) > 0 && path.Base(a[0]) == "taintwatch-launcher" {
				c.Name = "taintwatch-launcher"
				c.Args = a[1:]
			}
		}
		if c.Name == "taintwatch" || c.Name == "taintwatch.exe" || c.Name == "taintwatch-launcher" || strings.HasPrefix(c.Name, "taintwatch-linux-") || strings.HasPrefix(c.Name, "taintwatch-darwin-") {
			if len(c.Args) >= 2 && c.Args[0] == "policy" && contains(c.Args[1], "check", "show") {
				continue
			}
			if len(c.Args) == 0 || !contains(c.Args[0], "version", "status", "explain", "doctor", "replay", "--help", "-h") {
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
		bad = bad || contains(c.Name, "psql", "mysql", "mariadb", "sqlite3", "sqlcmd") && (strings.Contains(upper, "DROP TABLE") || strings.Contains(upper, "DROP DATABASE"))
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
	return decoderun.Analyze(in.Shell).Evidence()
}
