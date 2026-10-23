package rules

import (
	"path/filepath"
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/valuematch"
)

func valueMatch(in Input) []string {
	sensitive := sensitiveValueAction(in)
	var args []string
	if !sensitive {
		// Executable paths are sensitive, but printing an argument through a
		// harmless absolute executable (e.g. /usr/bin/printf) is not.
		if in.Tool == "Bash" {
			for _, c := range in.Shell.Commands {
				if strings.Contains(c.Executable, "/") {
					args = append(args, c.Executable)
				}
			}
		}
	} else if in.Tool == "Bash" {
		for _, c := range in.Shell.Commands {
			args = append(args, c.Executable)
			args = append(args, c.Args...)
		}
		args = append(args, in.Shell.Reads...)
		args = append(args, in.Shell.Writes...)
	} else if in.Tool == "WebFetch" {
		args = []string{in.URL}
	} else if in.FilePath != "" {
		args = []string{in.FilePath}
	}
	if len(args) == 0 {
		return nil
	}
	patterns := []valuematch.Pattern{}
	count, bytes := 0, 0
	// Recent provenance wins the bounded window. No contents or matched values
	// are returned as evidence or inserted into hook/audit reason strings.
	for i := len(in.Session.TaintEvents) - 1; i >= 0 && len(in.Session.TaintEvents)-i <= 128 && count < valuematch.MaxSessionValues; i-- {
		e := in.Session.TaintEvents[i]
		for j, v := range e.ValueMatches {
			if j >= valuematch.MaxValues || count >= valuematch.MaxSessionValues {
				break
			}
			if !valuematch.Valid(v) || valuematch.DomainOnlyAllowed(v, in.Policy.AllowedHosts) {
				continue
			}
			count++
			source := e.Tool
			if len(source) > 128 {
				source = source[:128]
			}
			source = strings.TrimSuffix(strings.TrimPrefix(strconv.QuoteToASCII(source), `"`), `"`)
			add := func(s string) {
				if len(s) >= 2 && len(s) <= 8*valuematch.MaxValueBytes && bytes+len(s) <= valuematch.MaxPatternBytes {
					patterns = append(patterns, valuematch.Pattern{Text: s, Source: source})
					bytes += len(s)
				}
			}
			add(v.Text)
			for k, s := range v.Variants {
				if k >= valuematch.MaxVariants {
					break
				}
				add(s)
			}
		}
	}
	if len(patterns) == 0 {
		return nil
	}
	m := valuematch.Compile(patterns)
	scanned := 0
	for _, arg := range args {
		if scanned >= valuematch.MaxTextBytes {
			break
		}
		if len(arg) > valuematch.MaxTextBytes-scanned {
			arg = arg[:valuematch.MaxTextBytes-scanned]
		}
		scanned += len(arg)
		if source, yes := m.Match(arg); yes {
			return []string{source}
		}
	}
	return nil
}

// Provenance alone is not a risky action. Ordinary in-project source reads and
// printed references must remain usable after web or MCP search results.
func sensitiveValueAction(in Input) bool {
	if in.Tool == "WebFetch" {
		return true
	}
	for _, predicate := range []func(Input) []string{secret, protected, self, publish, destructive, decodeRun, uncertain} {
		if len(predicate(in)) > 0 {
			return true
		}
	}
	if in.Tool == "Bash" {
		if len(in.Shell.Networks) > 0 {
			return true
		}
		for _, c := range in.Shell.Commands {
			if contains(c.Name, "sh", "bash", "zsh", "dash", "python", "python3", "node", "perl", "ruby", "eval", "source", ".") || c.Name == "go" && len(c.Args) > 0 && c.Args[0] == "run" {
				return true
			}
		}
	}
	if in.Tool == "Read" || in.Tool == "Write" || in.Tool == "Edit" || in.Tool == "Bash" {
		candidates := paths(in, in.Tool != "Read")
		for _, p := range candidates {
			for _, v := range variants(in, p) {
				if !filepath.IsAbs(v) {
					continue
				}
				rel, err := filepath.Rel(in.CWD, v)
				if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}
