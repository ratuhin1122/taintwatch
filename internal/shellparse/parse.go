package shellparse

import (
	"bytes"
	"net/url"
	"path"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command is a literal approximation; Dynamic means expansions remain unresolved.
type Command struct {
	Name    string
	Args    []string
	Dynamic bool
}
type Redirect struct {
	Operator, Path, Heredoc string
	Read, Write, Dynamic    bool
}
type Network struct {
	Command       string
	Hosts         []string
	LowConfidence bool
}

// Result retains structural facts without executing expansions or reading scripts.
type Result struct {
	// AST is the parsed root; consumers must treat it as read-only. Flattened
	// commands remain useful for extraction, but cannot establish data flow.
	AST                                           *syntax.File
	Commands                                      []Command
	Redirections                                  []Redirect
	Reads, Writes, URLs, Hosts                    []string
	Networks                                      []Network
	Operators                                     []string
	Pipelines, Substitutions, Subshells, Heredocs int
	Unparseable, Uncertain                        bool
}

// Parse bounds input and converts every parser failure into a conservative result.
func Parse(source string) (r Result) {
	return parse(source, 0)
}
func parse(source string, depth int) (r Result) {
	defer func() {
		if recover() != nil {
			r = Result{Unparseable: true, Uncertain: true}
		}
	}()
	if len(source) > 64<<10 || depth > 8 {
		return Result{Unparseable: true, Uncertain: true}
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(source), "")
	if err != nil {
		return Result{Unparseable: true, Uncertain: true}
	}
	r.AST = f
	syntax.Walk(f, func(n syntax.Node) bool {
		switch v := n.(type) {
		case *syntax.CallExpr:
			if len(v.Args) == 0 {
				return true
			}
			words := make([]string, len(v.Args))
			dynamic := false
			for i, w := range v.Args {
				s, ok := literal(w)
				words[i] = s
				dynamic = dynamic || !ok
			}
			words = Unwrap(words)
			if len(words) == 0 {
				r.Uncertain = true
				return true
			}
			c := Command{Name: path.Base(words[0]), Args: words[1:], Dynamic: dynamic}
			r.Commands = append(r.Commands, c)
			r.Uncertain = r.Uncertain || dynamic
			r.extract(c)
			if containsName(c.Name, "bash", "sh", "dash", "zsh") {
				found := false
				for i, a := range c.Args {
					if strings.HasPrefix(a, "-") && strings.Contains(a, "c") && i+1 < len(c.Args) {
						// Expansions are not literal shell source. Re-parsing the
						// <dynamic> placeholder creates a false syntax failure.
						index := len(v.Args) - len(words) + i + 2
						if code, ok := literal(v.Args[index]); ok {
							r.merge(parse(code, depth+1))
						} else {
							r.Uncertain = true
						}
						found = true
						break
					}
				}
				if !found {
					r.Uncertain = true
				}
			}
			if c.Name == "eval" {
				r.Uncertain = true
				if !dynamic {
					r.merge(parse(strings.Join(c.Args, " "), depth+1))
				}
			}
		case *syntax.Redirect:
			p, ok := literal(v.Word)
			op := v.Op.String()
			d := Redirect{Operator: op, Path: p, Dynamic: !ok}
			switch op {
			case "<":
				d.Read = true
			case ">", ">>", ">|", "&>", "&>>":
				d.Write = true
			case "<>":
				d.Read = true
				d.Write = true
			case ">&":
				if _, err := strconv.Atoi(p); err != nil && p != "-" {
					d.Write = true
				}
			}
			if v.Hdoc != nil {
				r.Heredocs++
				var b bytes.Buffer
				_ = syntax.NewPrinter().Print(&b, v.Hdoc)
				d.Heredoc = b.String()
			}
			r.Redirections = append(r.Redirections, d)
			r.Uncertain = r.Uncertain || !ok
			if d.Read {
				r.Reads = append(r.Reads, p)
			}
			if d.Write {
				r.Writes = append(r.Writes, p)
			}
		case *syntax.BinaryCmd:
			op := v.Op.String()
			r.Operators = append(r.Operators, op)
			if op == "|" || op == "|&" {
				r.Pipelines++
			}
		case *syntax.Stmt:
			if v.Semicolon.IsValid() {
				r.Operators = append(r.Operators, ";")
			}
		case *syntax.CmdSubst:
			r.Substitutions++
		case *syntax.Subshell:
			r.Subshells++
		case *syntax.FuncDecl:
			r.Uncertain = true
		}
		return true
	})
	return r
}

func containsName(s string, names ...string) bool {
	for _, n := range names {
		if n == s {
			return true
		}
	}
	return false
}
func (r *Result) merge(n Result) {
	r.Commands = append(r.Commands, n.Commands...)
	r.Reads = append(r.Reads, n.Reads...)
	r.Writes = append(r.Writes, n.Writes...)
	r.URLs = append(r.URLs, n.URLs...)
	r.Hosts = append(r.Hosts, n.Hosts...)
	r.Networks = append(r.Networks, n.Networks...)
	r.Redirections = append(r.Redirections, n.Redirections...)
	r.Operators = append(r.Operators, n.Operators...)
	r.Pipelines += n.Pipelines
	r.Substitutions += n.Substitutions
	r.Subshells += n.Subshells
	r.Heredocs += n.Heredocs
	r.Uncertain = r.Uncertain || n.Uncertain
	r.Unparseable = r.Unparseable || n.Unparseable
}

func literal(w *syntax.Word) (string, bool) {
	if w == nil {
		return "", false
	}
	return parts(w.Parts, false)
}

// Literal resolves static Bash quoting without performing expansions.
func Literal(w *syntax.Word) (string, bool) { return literal(w) }
func parts(ps []syntax.WordPart, quoted bool) (string, bool) {
	var b strings.Builder
	ok := true
	for _, p := range ps {
		switch v := p.(type) {
		case *syntax.Lit:
			s := v.Value
			for i := 0; i < len(s); i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
					if s[i] == '\n' {
						continue
					}
					if quoted && !strings.ContainsRune("$`\"\\", rune(s[i])) {
						b.WriteByte('\\')
					}
					b.WriteByte(s[i])
				} else {
					b.WriteByte(s[i])
				}
			}
		case *syntax.SglQuoted:
			if v.Dollar {
				s, k := ansi(v.Value)
				b.WriteString(s)
				ok = ok && k
			} else {
				b.WriteString(v.Value)
			}
		case *syntax.DblQuoted:
			s, k := parts(v.Parts, true)
			b.WriteString(s)
			ok = ok && k && !v.Dollar
		default:
			ok = false
			b.WriteString("<dynamic>")
		}
	}
	return b.String(), ok
}

// ansi resolves Bash's literal ANSI-C escapes; unsupported escapes stay uncertain.
func ansi(s string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return b.String(), false
		}
		switch s[i] {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte(27)
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\', '\'', '"':
			b.WriteByte(s[i])
		case '\n':
		default:
			base, max, start := uint64(8), 3, i
			if s[i] == 'x' {
				base = 16
				max = 2
				start = i + 1
			} else if s[i] == 'u' {
				base = 16
				max = 4
				start = i + 1
			} else if s[i] == 'U' {
				base = 16
				max = 8
				start = i + 1
			} else if s[i] < '0' || s[i] > '7' {
				return b.String(), false
			}
			end := start
			for end < len(s) && end < start+max {
				ch := s[end]
				if !(ch >= '0' && ch <= '7' || base == 16 && (ch >= '8' && ch <= '9' || ch >= 'a' && ch <= 'f' || ch >= 'A' && ch <= 'F')) {
					break
				}
				end++
			}
			if end == start {
				return b.String(), false
			}
			v, e := strconv.ParseUint(s[start:end], int(base), 32)
			if e != nil || v == 0 || v > 0x10ffff {
				return b.String(), false
			}
			if s[i] == 'u' || s[i] == 'U' {
				b.WriteRune(rune(v))
			} else {
				b.WriteByte(byte(v))
			}
			i = end - 1
		}
	}
	return b.String(), true
}

// Unwrap recognizes common command launchers. Unknown option forms stay uncertain
// at the rule layer; no wrapper or argument is ever executed.
func Unwrap(w []string) []string {
	for len(w) > 0 {
		name := path.Base(w[0])
		i := 1
		switch name {
		case "sudo", "env", "command", "builtin", "nohup", "timeout", "xargs", "nice":
			for i < len(w) {
				a := w[i]
				if a == "--" {
					i++
					break
				}
				if strings.HasPrefix(a, "-") {
					i++
					takesValue := (name == "sudo" && containsName(a, "-u", "-g", "-C", "--user", "--group", "--chdir")) || (name == "env" && containsName(a, "-u", "-C", "--unset", "--chdir")) || (name == "timeout" && containsName(a, "-k", "-s", "--kill-after", "--signal")) || (name == "xargs" && containsName(a, "-n", "-P", "-I", "-s", "--max-args", "--max-procs", "--replace")) || (name == "nice" && containsName(a, "-n", "--adjustment"))
					if takesValue {
						if i < len(w) {
							i++
						}
					}
					continue
				}
				if name == "env" && strings.Contains(a, "=") {
					i++
					continue
				}
				if name == "timeout" {
					i++
					name = "timeout-duration-consumed"
					continue
				}
				break
			}
			w = w[i:]
		default:
			return w
		}
	}
	return w
}

// Host extracts URL, scp-style, and SSH target hosts without suffix trust matching.
func Host(s string) string {
	if u, e := url.Parse(s); e == nil && u.Scheme != "" && u.Host != "" {
		return strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	}
	if strings.Contains(s, "://") {
		return ""
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	if s == "" || strings.ContainsAny(s, "/\\ <>$\n\r\t") || strings.HasPrefix(s, "-") {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}
func (r *Result) extract(c Command) {
	network := false
	low := false
	switch c.Name {
	case "curl", "wget", "nc", "ncat", "socat", "ssh", "scp", "rsync", "ftp":
		network = true
	case "git":
		for _, a := range c.Args {
			if a == "push" || a == "fetch" || a == "clone" || a == "pull" || a == "remote" {
				network = true
			}
		}
	case "pip", "pip3", "npm", "go":
		for _, a := range c.Args {
			if strings.Contains(a, "://") {
				network = true
			}
		}
	case "python", "python3", "node":
		s := strings.Join(c.Args, " ")
		for _, lib := range []string{"requests", "urllib", "http", "socket", "fetch(", "net."} {
			if strings.Contains(s, lib) {
				network = true
				low = true
			}
		}
	}
	var hosts []string
	for _, a := range c.Args {
		if (c.Name == "curl" || c.Name == "wget") && strings.HasPrefix(a, "@") {
			r.Reads = append(r.Reads, strings.TrimPrefix(a, "@"))
		}
		candidate := a
		if _, v, ok := strings.Cut(a, "="); ok && strings.Contains(v, "://") {
			candidate = v
		}
		if strings.Contains(candidate, "://") {
			r.URLs = append(r.URLs, candidate)
			if h := Host(candidate); h != "" {
				hosts = append(hosts, h)
			}
		} else if network && !strings.HasPrefix(candidate, "-") {
			if c.Name == "ssh" || c.Name == "scp" || c.Name == "rsync" || c.Name == "nc" || c.Name == "ncat" || c.Name == "ftp" || c.Name == "socat" || strings.Contains(candidate, "@") {
				if h := Host(candidate); h != "" {
					hosts = append(hosts, h)
				}
			}
		}
	}
	if network {
		r.Networks = append(r.Networks, Network{Command: c.Name, Hosts: hosts, LowConfidence: low})
		r.Hosts = append(r.Hosts, hosts...)
	}
	// Literal operands are candidates, not a claim about actual filesystem access.
	switch c.Name {
	case "cat", "head", "tail", "less", "more", "grep", "rg", "sed", "awk", "cp", "mv", "tar", "source", ".", "base64", "xxd":
		for _, a := range c.Args {
			if !strings.HasPrefix(a, "-") {
				r.Reads = append(r.Reads, a)
			}
		}
	}
	switch c.Name {
	case "tee", "touch", "truncate", "rm", "cp", "mv", "install":
		for _, a := range c.Args {
			if !strings.HasPrefix(a, "-") {
				r.Writes = append(r.Writes, a)
			}
		}
	}
}
