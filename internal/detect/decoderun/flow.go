package decoderun

import (
	"path"
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

type origin uint8

const (
	decoded origin = 1 << iota
	downloaded
)

// Finding contains constant descriptions only; no script, payload, URL or path
// is copied to audit evidence. Incomplete means analysis hit a supported bound.
type Finding struct{ Decode, Download, Incomplete bool }

func (f Finding) Matched() bool { return f.Decode || f.Download }
func (f Finding) Evidence() []string {
	if f.Decode {
		return []string{"decoded input reaches executable code"}
	}
	if f.Download {
		return []string{"downloaded input reaches executable code"}
	}
	return nil
}

type value struct {
	data, file origin
	text       string
	literal    bool
}
type environment map[string]value

func clone(e environment) environment {
	n := environment{}
	for k, v := range e {
		n[k] = v
	}
	return n
}

type analyzer struct {
	finding Finding
	nodes   int
}

func (a *analyzer) hit(o origin) {
	a.finding.Decode = a.finding.Decode || o&decoded != 0
	a.finding.Download = a.finding.Download || o&downloaded != 0
}
func (a *analyzer) budget(depth int) bool {
	a.nodes++
	if depth > 32 || a.nodes > 20000 {
		a.finding.Incomplete = true
		return false
	}
	return true
}

// Analyze inspects the root AST. A parse error has no invented decoder match;
// shellparse.Unparseable/Uncertain remain available to the caller's fail policy.
func Analyze(parsed shellparse.Result) Finding {
	if parsed.AST == nil {
		return Finding{Incomplete: parsed.Unparseable}
	}
	a := analyzer{}
	a.list(parsed.AST.Stmts, value{}, environment{}, 0)
	return a.finding
}
func (a *analyzer) list(stmts []*syntax.Stmt, input value, env environment, depth int) value {
	output := value{literal: true}
	for _, s := range stmts {
		v := a.stmt(s, input, env, depth+1)
		output.data |= v.data
		output.literal = output.literal && v.literal
		if len(output.text)+len(v.text) <= 64<<10 {
			output.text += v.text
		} else {
			output.text = ""
			output.literal = false
			a.finding.Incomplete = true
		}
	}
	return output
}
func (a *analyzer) script(code string, input value, env environment, depth int) value {
	if !a.budget(depth) {
		return value{}
	}
	p := shellparse.Parse(code)
	if p.AST == nil {
		a.finding.Incomplete = true
		return value{}
	}
	return a.list(p.AST.Stmts, input, clone(env), depth+1)
}
func (a *analyzer) stmt(s *syntax.Stmt, input value, env environment, depth int) value {
	if s == nil || !a.budget(depth) {
		return value{}
	}
	outputRedirected := false
	for _, r := range s.Redirs {
		w := a.word(r.Word, input, env, depth+1)
		fd := ""
		if r.N != nil {
			fd = r.N.Value
		}
		switch r.Op {
		case syntax.RdrIn, syntax.RdrInOut:
			if fd == "" || fd == "0" {
				input = value{data: w.file}
			}
		case syntax.WordHdoc:
			if fd == "" || fd == "0" {
				input = w
			}
		case syntax.Hdoc, syntax.DashHdoc:
			if fd == "" || fd == "0" {
				input = a.word(r.Hdoc, input, env, depth+1)
			}
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut:
			if fd == "" || fd == "1" {
				outputRedirected = true
			}
		case syntax.RdrAll, syntax.AppAll:
			outputRedirected = true
		case syntax.DplOut:
			if fd == "" || fd == "1" {
				if w.text != "1" {
					outputRedirected = true
				}
			}
		case syntax.DplIn:
			if fd == "" || fd == "0" {
				input = value{}
			}
		}
	}
	var out value
	switch c := s.Cmd.(type) {
	case *syntax.CallExpr:
		out = a.call(c, input, env, depth+1)
	case *syntax.BinaryCmd:
		if c.Op == syntax.Pipe || c.Op == syntax.PipeAll {
			left := a.stmt(c.X, input, clone(env), depth+1)
			out = a.stmt(c.Y, left, clone(env), depth+1)
		} else {
			x := a.stmt(c.X, input, env, depth+1)
			y := a.stmt(c.Y, input, env, depth+1)
			out.data = x.data | y.data
		}
	case *syntax.Block:
		out = a.list(c.Stmts, input, env, depth+1)
	case *syntax.Subshell:
		out = a.list(c.Stmts, input, clone(env), depth+1)
	case *syntax.IfClause:
		a.list(c.Cond, input, clone(env), depth+1)
		out = a.list(c.Then, input, clone(env), depth+1)
		if c.Else != nil {
			out.data |= a.stmt(&syntax.Stmt{Cmd: c.Else}, input, clone(env), depth+1).data
		}
	case *syntax.WhileClause:
		a.list(c.Cond, input, clone(env), depth+1)
		out = a.list(c.Do, input, clone(env), depth+1)
	case *syntax.ForClause:
		if loop, ok := c.Loop.(*syntax.WordIter); ok {
			for _, w := range loop.Items {
				a.word(w, input, env, depth+1)
			}
		} else {
			a.embedded(c.Loop, input, env, depth+1)
		}
		out = a.list(c.Do, input, clone(env), depth+1)
	case *syntax.CaseClause:
		a.word(c.Word, input, env, depth+1)
		for _, item := range c.Items {
			for _, w := range item.Patterns {
				a.word(w, input, env, depth+1)
			}
			out.data |= a.list(item.Stmts, input, clone(env), depth+1).data
		}
	case *syntax.TimeClause:
		out = a.stmt(c.Stmt, input, env, depth+1)
	case *syntax.DeclClause:
		for _, assign := range c.Args {
			a.assignment(assign, input, env, depth+1)
		}
	case *syntax.FuncDecl:
		// Function declarations are definitions, not invocations. Their bodies are
		// intentionally not treated as executed; unresolved calls remain a limitation.
	default:
		a.embedded(s.Cmd, input, env, depth+1)
	}
	for _, r := range s.Redirs {
		if r.Word != nil {
			syntax.Walk(r.Word, func(n syntax.Node) bool {
				if p, ok := n.(*syntax.ProcSubst); ok && p.Op == syntax.CmdOut {
					a.list(p.Stmts, out, clone(env), depth+1)
					return false
				}
				return true
			})
		}
	}
	if outputRedirected {
		out.data = 0
		out.literal = false
	}
	return out
}

// Arithmetic, tests, loop expressions, and other non-call positions may execute
// nested substitutions too. Inspect those executions without mislabeling their
// numeric/boolean results as decoded script text.
func (a *analyzer) embedded(node syntax.Node, input value, env environment, depth int) {
	if node == nil || !a.budget(depth) {
		return
	}
	syntax.Walk(node, func(n syntax.Node) bool {
		if !a.budget(depth) {
			return false
		}
		switch p := n.(type) {
		case *syntax.CmdSubst:
			a.list(p.Stmts, input, clone(env), depth+1)
			return false
		case *syntax.ProcSubst:
			a.list(p.Stmts, value{}, clone(env), depth+1)
			return false
		case *syntax.FuncDecl:
			return false
		}
		return true
	})
}
func (a *analyzer) assignment(as *syntax.Assign, input value, env environment, depth int) {
	if as == nil || as.Name == nil {
		return
	}
	if _, ok := env[as.Name.Value]; !ok && len(env) >= 128 {
		a.finding.Incomplete = true
		return
	}
	v := a.word(as.Value, input, env, depth+1)
	if as.Array != nil {
		a.embedded(as.Array, input, env, depth+1)
	}
	if as.Append {
		old := env[as.Name.Value]
		v.data |= old.data
		v.literal = v.literal && old.literal
		if len(old.text)+len(v.text) <= 64<<10 {
			v.text = old.text + v.text
		} else {
			v.text = ""
			v.literal = false
			a.finding.Incomplete = true
		}
	}
	env[as.Name.Value] = v
}
func (a *analyzer) word(w *syntax.Word, input value, env environment, depth int) value {
	if w == nil || !a.budget(depth) {
		return value{}
	}
	if text, ok := shellparse.Literal(w); ok {
		return value{text: text, literal: true}
	}
	out := value{literal: true}
	for _, part := range w.Parts {
		var v value
		switch p := part.(type) {
		case *syntax.DblQuoted:
			v = a.word(&syntax.Word{Parts: p.Parts}, input, env, depth+1)
		case *syntax.CmdSubst:
			v = a.list(p.Stmts, input, clone(env), depth+1)
			v.text = strings.TrimRight(v.text, "\n")
		case *syntax.ProcSubst:
			if p.Op == syntax.CmdIn {
				v.file = a.list(p.Stmts, input, clone(env), depth+1).data
			} else {
				// Output process substitution receives a producer's stdout later.
				// Its body is also inspected now for independent execution flows.
				a.list(p.Stmts, value{}, clone(env), depth+1)
			}
		case *syntax.ParamExp:
			if p.Param != nil {
				v = env[p.Param.Value]
			}
			if p.Exp != nil {
				extra := a.word(p.Exp.Word, input, env, depth+1)
				v.data |= extra.data
				v.file |= extra.file
				v.literal = false
			}
			if p.Excl || p.Length || p.Index != nil || p.Slice != nil || p.Repl != nil {
				v.literal = false
			}
		default:
			v.text, v.literal = shellparse.Literal(&syntax.Word{Parts: []syntax.WordPart{part}})
			if !v.literal {
				a.embedded(part, input, env, depth+1)
			}
		}
		out.data |= v.data
		out.file |= v.file
		if len(out.text)+len(v.text) <= 64<<10 {
			out.text += v.text
		} else {
			out.text = ""
			out.literal = false
			a.finding.Incomplete = true
		}
		out.literal = out.literal && v.literal
	}
	return out
}
func (a *analyzer) call(c *syntax.CallExpr, input value, env environment, depth int) value {
	if !a.budget(depth) {
		return value{}
	}
	if len(c.Args) == 0 {
		for _, as := range c.Assigns {
			a.assignment(as, input, env, depth+1)
		}
		return value{}
	}
	words := make([]value, len(c.Args))
	names := make([]string, len(c.Args))
	for i, w := range c.Args {
		words[i] = a.word(w, input, env, depth+1)
		names[i] = words[i].text
		if !words[i].literal {
			names[i] = "<dynamic>"
		}
	}
	unwrapped := shellparse.Unwrap(names)
	if len(unwrapped) == 0 {
		return value{}
	}
	words = words[len(names)-len(unwrapped):]
	if !words[0].literal {
		a.hit(words[0].data)
		return value{}
	}
	name := path.Base(words[0].text)
	args := words[1:]
	stringsArgs := make([]string, len(args))
	for i, v := range args {
		stringsArgs[i] = v.text
	}
	childEnv := clone(env)
	for _, as := range c.Assigns {
		a.assignment(as, input, childEnv, depth+1)
	}
	if sourceCommand(name) {
		if len(args) > 0 {
			a.hit(args[0].file)
			if stdinFile(args[0].text) {
				a.hit(input.data)
			}
		}
		return value{}
	}
	if name == "eval" {
		var code strings.Builder
		literal := true
		for i, v := range args {
			a.hit(v.data)
			literal = literal && v.literal
			if i > 0 {
				code.WriteByte(' ')
			}
			code.WriteString(v.text)
		}
		if literal && len(args) > 0 {
			a.script(code.String(), input, childEnv, depth+1)
		}
		return value{}
	}
	if interpreter(name) {
		// Shell quoting can concatenate the option and its code into one AST word.
		for i, v := range args {
			prefix := ""
			if strings.HasPrefix(name, "python") && strings.HasPrefix(v.text, "-c") && len(v.text) > 2 {
				prefix = "-c"
			}
			if (name == "node" || name == "nodejs" || name == "perl" || name == "ruby") && strings.HasPrefix(v.text, "-e") && len(v.text) > 2 {
				prefix = "-e"
			}
			if (name == "node" || name == "nodejs") && strings.HasPrefix(v.text, "--eval=") {
				prefix = "--eval="
			}
			if prefix != "" {
				code := v
				code.text = strings.TrimPrefix(code.text, prefix)
				option := strings.TrimSuffix(prefix, "=")
				args = append(append(append([]value{}, args[:i]...), value{text: option, literal: true}, code), args[i+1:]...)
				break
			}
		}
		stringsArgs = make([]string, len(args))
		for i, v := range args {
			stringsArgs[i] = v.text
		}
		codeIndex, scriptIndex, stdin := executionArgs(name, stringsArgs)
		if codeIndex >= 0 {
			v := args[codeIndex]
			a.hit(v.data)
			if v.literal {
				if shell(name) {
					for j := codeIndex + 1; j < len(args) && j-codeIndex < 128; j++ {
						childEnv[strconv.Itoa(j-codeIndex-1)] = args[j]
					}
					return a.script(v.text, input, childEnv, depth+1)
				} else {
					return value{data: a.foreign(v.text, input.data, depth+1)}
				}
			}
		} else if scriptIndex >= 0 {
			a.hit(args[scriptIndex].file)
			if stdinFile(args[scriptIndex].text) {
				a.hit(input.data)
			}
		} else if stdin {
			a.hit(input.data)
			if input.literal {
				if shell(name) {
					return a.script(input.text, value{}, childEnv, depth+1)
				} else {
					return value{data: a.foreign(input.text, 0, depth+1)}
				}
			}
		}
		return value{}
	}
	if kind, toStdout := producer(name, stringsArgs); kind != 0 {
		if toStdout {
			return value{data: kind}
		}
		return value{}
	}
	switch name {
	case "echo", "printf":
		var out value
		for _, v := range args {
			out.data |= v.data
		}
		if text, ok := constantOutput(name, args); ok {
			out.literal = true
			out.text = text
		}
		return out
	case "cat":
		out := value{}
		files := 0
		stdin := false
		plain := true
		options := true
		for _, v := range args {
			if options && v.text == "--" {
				options = false
				continue
			}
			if options && strings.HasPrefix(v.text, "-") && v.text != "-" {
				plain = false
				continue
			}
			if v.text == "-" {
				stdin = true
			} else {
				files++
				out.data |= v.file
			}
		}
		if files == 0 {
			stdin = true
		}
		if stdin {
			out.data |= input.data
		}
		if plain && files == 0 {
			out.text = input.text
			out.literal = input.literal
		}
		return out
	case "tee", "head", "tail", "grep", "rg", "sed", "awk", "tr", "cut", "sort", "uniq":
		out := value{data: input.data}
		for _, v := range args {
			out.data |= v.file
		}
		return out
	}
	return value{}
}

// Only side-effect-free literal output is folded; printf %b and option dialects
// remain unknown. This recognizes nested literal script construction without
// treating quoted examples printed for the user as execution themselves.
func constantOutput(name string, args []value) (string, bool) {
	for _, v := range args {
		if !v.literal {
			return "", false
		}
	}
	if name == "echo" {
		newline := true
		if len(args) > 0 && args[0].text == "-n" {
			args = args[1:]
			newline = false
		}
		parts := []string{}
		for _, v := range args {
			if strings.HasPrefix(v.text, "-") || strings.Contains(v.text, "\\") {
				return "", false
			}
			parts = append(parts, v.text)
		}
		text := strings.Join(parts, " ")
		if newline {
			text += "\n"
		}
		return text, len(text) <= 64<<10
	}
	if len(args) == 0 {
		return "", true
	}
	format := args[0].text
	index := 1
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			i++
			if format[i] == '%' {
				b.WriteByte('%')
			} else if format[i] == 's' {
				if index < len(args) {
					b.WriteString(args[index].text)
					index++
				}
			} else {
				return "", false
			}
		} else {
			b.WriteByte(format[i])
		}
		if b.Len() > 64<<10 {
			return "", false
		}
	}
	// Shell printf repeats the format for surplus arguments; do not invent output.
	if index < len(args) {
		return "", false
	}
	return b.String(), true
}
func sourceCommand(n string) bool { return n == "source" || n == "." }
func stdinFile(n string) bool     { return n == "/dev/stdin" || n == "/dev/fd/0" || n == "/proc/self/fd/0" }
func shell(n string) bool         { return n == "sh" || n == "bash" || n == "zsh" || n == "dash" || n == "ksh" }
func interpreter(n string) bool {
	if shell(n) || n == "node" || n == "nodejs" || n == "perl" || n == "ruby" {
		return true
	}
	if strings.HasPrefix(n, "python") {
		v := strings.TrimPrefix(n, "python")
		for _, r := range v {
			if (r < '0' || r > '9') && r != '.' {
				return false
			}
		}
		return true
	}
	return false
}
func informational(args []string) bool {
	for _, v := range args {
		if v == "--" {
			break
		}
		if v == "--help" || v == "--version" {
			return true
		}
	}
	return false
}

// executionArgs distinguishes script stdin from data stdin (e.g. python file.py
// or bash -c 'echo ok'). Return the precise code/file argument when present.
func executionArgs(name string, args []string) (code, file int, stdin bool) {
	code, file = -1, -1
	for i := 0; i < len(args); i++ {
		v := args[i]
		if v == "--" {
			if i+1 < len(args) {
				return -1, i + 1, false
			}
			return -1, -1, true
		}
		if v == "-" {
			return -1, -1, true
		}
		if shell(name) && shortFlag(v, 'n') {
			return -1, -1, false
		}
		flag := v == "-c" && shell(name) || strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") && shell(name) && strings.Contains(v, "c") || strings.HasPrefix(name, "python") && v == "-c" || (name == "node" || name == "nodejs") && (v == "-e" || v == "--eval") || (name == "perl" || name == "ruby") && v == "-e"
		if flag {
			if i+1 < len(args) {
				return i + 1, -1, false
			}
			return -1, -1, false
		}
		if strings.HasPrefix(name, "python") && v == "-m" || v == "--check" || (name == "node" || name == "nodejs" || name == "ruby" || name == "perl") && v == "-c" || v == "--version" || v == "--help" || shell(name) && (v == "-n" || v == "-o" && i+1 < len(args) && args[i+1] == "noexec") {
			return -1, -1, false
		}
		if v == "-o" || v == "-O" || v == "--require" || v == "-r" {
			i++
			continue
		}
		if !strings.HasPrefix(v, "-") {
			return -1, i, false
		}
	}
	return -1, -1, true
}
func shortFlag(arg string, r rune) bool {
	if len(arg) < 2 || arg[0] != '-' || strings.HasPrefix(arg, "--") {
		return false
	}
	return strings.ContainsRune(arg[1:], r)
}
func producer(name string, args []string) (origin, bool) {
	if informational(args) {
		return 0, false
	}
	decoder := false
	stdout := true
	options := true
	positionals := 0
	skipValue := false
	for i, v := range args {
		if skipValue {
			skipValue = false
			continue
		}
		if v == "--" {
			options = false
			continue
		}
		if !options || !strings.HasPrefix(v, "-") {
			positionals++
		}
		if !options {
			continue
		}
		if name == "xxd" && oneOf(v, "-c", "-g", "-l", "-s", "-o") {
			skipValue = true
			continue
		}
		switch name {
		case "base64":
			decoder = decoder || v == "--decode" || shortFlag(v, 'd') || shortFlag(v, 'D')
			if v == "-o" || v == "--output" {
				stdout = i+1 < len(args) && (args[i+1] == "-" || args[i+1] == "/dev/stdout")
			}
			if strings.HasPrefix(v, "--output=") {
				target := strings.TrimPrefix(v, "--output=")
				stdout = target == "-" || target == "/dev/stdout"
			}
			if strings.HasPrefix(v, "-o") && len(v) > 2 {
				stdout = v[2:] == "-" || v[2:] == "/dev/stdout"
			}
		case "xxd":
			decoder = decoder || shortFlag(v, 'r')
		case "openssl":
			decoder = decoder || v == "-d"
			if v == "-out" && i+1 < len(args) && args[i+1] != "-" && args[i+1] != "/dev/stdout" {
				stdout = false
			}
		}
	}
	if name == "xxd" && positionals >= 2 {
		stdout = false
	}
	if name == "openssl" && (len(args) == 0 || args[0] != "enc") {
		decoder = false
	}
	if decoder {
		return decoded, stdout
	}
	if name == "curl" {
		for i, v := range args {
			if v == "-o" || v == "--output" {
				if i+1 < len(args) && args[i+1] != "-" {
					stdout = false
				}
			}
			if v == "-O" || v == "--remote-name" {
				stdout = false
			}
			if strings.HasPrefix(v, "--output=") {
				stdout = strings.TrimPrefix(v, "--output=") == "-"
			}
			if strings.HasPrefix(v, "-o") && len(v) > 2 {
				stdout = v[2:] == "-"
			}
		}
		return downloaded, stdout
	}
	if name == "wget" {
		stdout = false
		for i, v := range args {
			if (v == "-O" || v == "--output-document") && i+1 < len(args) && args[i+1] == "-" || v == "-O-" || v == "--output-document=-" {
				stdout = true
			}
			if strings.HasPrefix(v, "-") && !strings.HasPrefix(v, "--") {
				if j := strings.IndexByte(v, 'O'); j > 0 {
					stdout = v[j+1:] == "-" || v[j+1:] == "" && i+1 < len(args) && args[i+1] == "-"
				}
			}
		}
		return downloaded, stdout
	}
	return 0, false
}
