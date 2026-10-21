package taint

import (
	"errors"
	"path"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
)

var errCommandTooLarge = errors.New("shell source scan exceeds 64 KiB")

// commandWords uses Bash AST facts. On malformed input only, the legacy lexer
// recovers unfinished literal reader prefixes; it never executes expansions.
func commandWords(command string) ([][]string, error) {
	if len(command) > 64<<10 {
		return nil, errCommandTooLarge
	}
	parsed := shellparse.Parse(command)
	if !parsed.Unparseable {
		var commands [][]string
		for _, c := range parsed.Commands {
			commands = append(commands, append([]string{c.Name}, c.Args...))
		}
		if parsed.Uncertain {
			return commands, errors.New("unresolved shell expansion")
		}
		return commands, nil
	}
	var commands [][]string
	var words []string
	var word strings.Builder
	var quote byte
	escaped, started, comment := false, false, false
	flushWord := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	flushCommand := func() {
		flushWord()
		if len(words) > 0 {
			commands = append(commands, words)
			words = nil
		}
	}
	for i := 0; i < len(command); i++ {
		ch := command[i]
		if comment {
			if ch == '\n' {
				comment = false
				flushCommand()
			}
			continue
		}
		if escaped {
			if ch != '\n' {
				word.WriteByte(ch)
				started = true
			}
			escaped = false
			continue
		}
		if quote == '\'' {
			if ch == '\'' {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if quote == '"' {
			if ch == '"' {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '\'', '"':
			quote = ch
			started = true
		case ' ', '\t', '\r':
			flushWord()
		case ';', '|', '&', '\n', '(', ')':
			flushCommand()
		case '#':
			if !started {
				comment = true
			} else {
				word.WriteByte(ch)
			}
		default:
			word.WriteByte(ch)
			started = true
		}
	}
	if quote != 0 || escaped {
		flushCommand()
		return commands, errors.New("ambiguous shell words")
	}
	flushCommand()
	return commands, nil
}

func (c *Classifier) reader(words []string) bool {
	i := 0
	for i < len(words) {
		word := words[i]
		if assignment(word) || word == "env" || word == "command" || word == "sudo" || word == "!" || word == "if" || word == "then" || word == "do" {
			i++
			continue
		}
		break
	}
	words = words[i:]
	if len(words) == 0 {
		return false
	}
	for _, prefix := range c.readers {
		if len(words) < len(prefix) {
			continue
		}
		ok := path.Base(words[0]) == prefix[0]
		for j := 1; j < len(prefix) && ok; j++ {
			ok = words[j] == prefix[j]
		}
		if ok {
			return true
		}
	}
	return false
}

func assignment(word string) bool {
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false
	}
	for i, c := range name {
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
