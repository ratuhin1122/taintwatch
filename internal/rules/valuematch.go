package rules

import (
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/valuematch"
)

func valueMatch(in Input) []string {
	var args []string
	if in.Tool == "Bash" {
		for _, c := range in.Shell.Commands {
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
