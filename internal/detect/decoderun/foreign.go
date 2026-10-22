package decoderun

import (
	"strconv"
	"strings"
)

// Shell ASTs isolate the actual -c/-e argument. This bounded expression scanner
// then builds call/argument relationships inside that literal. It is not a full
// Python/JavaScript parser: strings/comments are data, and a decoder must feed an
// execution call (possibly through a simple assignment), not merely coexist.
type token struct {
	text   string
	quoted bool
}

func lex(code string) []token {
	var out []token
	for i := 0; i < len(code) && len(out) < 16000; {
		c := code[i]
		if c == ' ' || c == '\t' || c == '\r' {
			i++
			continue
		}
		if c == '#' || c == '/' && i+1 < len(code) && code[i+1] == '/' {
			for i < len(code) && code[i] != '\n' {
				i++
			}
			continue
		}
		if c == '/' && i+1 < len(code) && code[i+1] == '*' {
			i += 2
			for i+1 < len(code) && code[i:i+2] != "*/" {
				i++
			}
			if i+1 < len(code) {
				i += 2
			}
			continue
		}
		if c == '/' && (len(out) == 0 || oneOf(out[len(out)-1].text, "(", "=", ",", "[", ":", "return")) {
			// JavaScript regex literals are quoted data, not executable call syntax.
			i++
			class := false
			for i < len(code) {
				if code[i] == '\\' && i+1 < len(code) {
					i += 2
					continue
				}
				if code[i] == '[' {
					class = true
				}
				if code[i] == ']' {
					class = false
				}
				if code[i] == '/' && !class {
					i++
					break
				}
				i++
			}
			for i < len(code) && identByte(code[i]) {
				i++
			}
			out = append(out, token{text: "<regex>", quoted: true})
			continue
		}
		if c == '\'' || c == '"' || c == '`' {
			quote := c
			i++
			triple := i+1 < len(code) && code[i] == quote && code[i+1] == quote
			if triple {
				i += 2
			}
			var b strings.Builder
			for i < len(code) {
				if code[i] == quote {
					if !triple {
						i++
						break
					}
					if i+2 < len(code) && code[i+1] == quote && code[i+2] == quote {
						i += 3
						break
					}
				}
				if code[i] == '\\' && i+1 < len(code) {
					i++
					switch code[i] {
					case 'x', 'u':
						digits := 2
						if code[i] == 'u' {
							digits = 4
						}
						if i+digits < len(code) {
							if n, e := strconv.ParseUint(code[i+1:i+1+digits], 16, 32); e == nil {
								b.WriteRune(rune(n))
								i += digits + 1
								continue
							}
						}
					case 'n':
						b.WriteByte('\n')
						i++
						continue
					case 'r':
						b.WriteByte('\r')
						i++
						continue
					case 't':
						b.WriteByte('\t')
						i++
						continue
					}
					b.WriteByte(code[i])
					i++
					continue
				}
				b.WriteByte(code[i])
				i++
			}
			out = append(out, token{b.String(), true})
			continue
		}
		if identByte(c) {
			start := i
			i++
			for i < len(code) && identByte(code[i]) {
				i++
			}
			out = append(out, token{text: code[start:i]})
			continue
		}
		out = append(out, token{text: string(c)})
		i++
	}
	return out
}
func identByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$'
}

type expression struct {
	flow     origin
	text     string
	constant bool
}
type foreignParser struct {
	a                 *analyzer
	t                 []token
	i, depth, nesting int
	env               map[string]expression
	input, output     origin
}

func (a *analyzer) foreign(code string, input origin, depth int) origin {
	if !a.budget(depth) {
		return 0
	}
	p := foreignParser{a: a, t: lex(code), depth: depth, env: map[string]expression{}, input: input}
	if len(p.t) >= 16000 {
		a.finding.Incomplete = true
	}
	for p.i < len(p.t) {
		start := p.i
		if !p.t[p.i].quoted && p.i+1 < len(p.t) && p.t[p.i+1].text == "=" && (p.i+2 >= len(p.t) || p.t[p.i+2].text != "=") {
			name := p.t[p.i].text
			p.i += 2
			v := p.sequence(";", "\n")
			p.env[name] = v
		} else {
			p.primary(0)
		}
		if p.i <= start {
			p.i++
		}
	}
	return p.output
}
func (p *foreignParser) sequence(stops ...string) expression {
	out := expression{}
	for p.i < len(p.t) {
		if !p.t[p.i].quoted && oneOf(p.t[p.i].text, stops...) {
			break
		}
		before := p.i
		v := p.primary(0)
		out.flow |= v.flow
		if p.i == before {
			p.i++
		}
	}
	return out
}
func (p *foreignParser) primary(level int) expression {
	p.nesting++
	defer func() { p.nesting-- }()
	if p.i >= len(p.t) || !p.a.budget(p.depth+p.nesting) {
		p.i = len(p.t)
		return expression{}
	}
	t := p.t[p.i]
	p.i++
	if t.quoted {
		return expression{text: t.text, constant: true}
	}
	if oneOf(t.text, "(", "[", "{") {
		close := map[string]string{"(": ")", "[": "]", "{": "}"}[t.text]
		v := p.sequence(close)
		if p.i < len(p.t) {
			p.i++
		}
		return v
	}
	if t.text == ";" || t.text == "\n" {
		return expression{}
	}
	name := t.text
	v := p.env[name]
	for p.i+1 < len(p.t) && p.t[p.i].text == "." && !p.t[p.i+1].quoted {
		name += "." + p.t[p.i+1].text
		p.i += 2
	}
	if oneOf(name, "sys.stdin", "sys.stdin.buffer", "process.stdin") {
		v.flow |= p.input
	}
	for p.i < len(p.t) {
		if p.t[p.i].text != "(" {
			break
		}
		p.i++
		args := []expression{}
		for p.i < len(p.t) && p.t[p.i].text != ")" {
			before := p.i
			arg := expression{}
			for p.i < len(p.t) && p.t[p.i].text != "," && p.t[p.i].text != ")" {
				x := p.primary(level + 1)
				arg.flow |= x.flow
				if x.constant {
					arg.text = x.text
					arg.constant = true
				}
			}
			args = append(args, arg)
			if p.i < len(p.t) && p.t[p.i].text == "," {
				p.i++
			}
			if p.i == before {
				p.i++
			}
		}
		if p.i < len(p.t) && p.t[p.i].text == ")" {
			p.i++
		}
		flow := v.flow
		for _, arg := range args {
			flow |= arg.flow
		}
		if decodeFunction(name, args) {
			flow |= decoded
		}
		if executionFunction(name) {
			p.a.hit(flow)
		}
		if oneOf(name, "print", "console.log", "sys.stdout.write", "sys.stdout.buffer.write", "process.stdout.write") {
			p.output |= flow
			flow = 0
		}
		if oneOf(name, "len", "bool", "int", "float") {
			flow = 0
		}
		v = expression{flow: flow}
		if p.i+1 < len(p.t) && p.t[p.i].text == "." {
			name = p.t[p.i+1].text
			p.i += 2
			continue
		}
	}
	return v
}
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func decodeFunction(name string, args []expression) bool {
	if oneOf(name, "base64.b64decode", "base64.standard_b64decode", "base64.urlsafe_b64decode", "base64.decodebytes", "b64decode", "urlsafe_b64decode", "decodebytes", "binascii.a2b_base64", "binascii.unhexlify", "bytes.fromhex", "bytearray.fromhex", "atob", "globalThis.atob") {
		return true
	}
	return (name == "Buffer.from" || name == "Buffer") && len(args) >= 2 && args[1].constant && oneOf(strings.ToLower(args[1].text), "base64", "base64url", "hex")
}
func executionFunction(name string) bool {
	return oneOf(name, "exec", "eval", "builtins.exec", "builtins.eval", "global.eval", "globalThis.eval", "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen", "child_process.exec", "child_process.execSync", "child_process.spawn", "child_process.spawnSync", "vm.runInThisContext", "vm.runInNewContext")
}
