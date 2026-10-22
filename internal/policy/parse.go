package policy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"gopkg.in/yaml.v3"
)

const MaxBytes = 1 << 20

type change struct {
	key  string
	node *yaml.Node
}
type Document struct{ changes []change }

var schema = map[string][]string{
	"":        {"version", "fail_mode", "profile", "allow_project_loosening", "sources", "egress", "secrets", "protected_writes", "rules", "log", "state"},
	"sources": {"tools", "mcp", "bash", "read"}, "sources.mcp": {"trusted_servers"}, "sources.bash": {"reader_commands"}, "sources.read": {"taint_globs", "temp_paths", "downloaded_paths"},
	"egress": {"allow_domains"}, "secrets": {"paths"}, "log": {"path", "rotation"}, "log.rotation": {"max_bytes", "keep"}, "state": {"retention_days"}, "rules": RuleIDs,
}
var listKeys = map[string]bool{"sources.tools": true, "sources.mcp.trusted_servers": true, "sources.bash.reader_commands": true, "sources.read.taint_globs": true, "sources.read.temp_paths": true, "sources.read.downloaded_paths": true, "egress.allow_domains": true, "secrets.paths": true, "protected_writes": true}

func isList(k string) bool {
	return listKeys[k] || strings.HasPrefix(k, "rules.") && strings.HasSuffix(k, ".extra_match")
}
func problem(n *yaml.Node, message string) error { return fmt.Errorf("line %d: %s", n.Line, message) }

// Parse validates a single strict version-1 document, including value types and
// duplicate keys. Aliases, anchors, merge keys and custom tags are not supported.
func Parse(data []byte) (Document, error) {
	if len(data) > MaxBytes {
		return Document{}, fmt.Errorf("policy exceeds 1 MiB")
	}
	d := yaml.NewDecoder(bytes.NewReader(data))
	var root yaml.Node
	if e := d.Decode(&root); e != nil {
		return Document{}, fmt.Errorf("invalid YAML: %w", e)
	}
	var extra yaml.Node
	if e := d.Decode(&extra); e != io.EOF {
		return Document{}, fmt.Errorf("line %d: only one YAML document is allowed", extra.Line)
	}
	if len(root.Content) != 1 {
		return Document{}, fmt.Errorf("line 1: policy must be a mapping")
	}
	count := 0
	var safe func(*yaml.Node, int) error
	safe = func(n *yaml.Node, depth int) error {
		count++
		if depth > 20 || count > 20000 {
			return problem(n, "policy structure exceeds limits")
		}
		if n.Anchor != "" || n.Kind == yaml.AliasNode {
			return problem(n, "YAML anchors and aliases are not allowed")
		}
		if n.Tag != "" && !has([]string{"!!map", "!!seq", "!!str", "!!int", "!!bool", "!!null", "!!float"}, n.Tag) {
			return problem(n, "custom YAML tags are not allowed")
		}
		for _, v := range n.Content {
			if e := safe(v, depth+1); e != nil {
				return e
			}
		}
		return nil
	}
	if e := safe(&root, 0); e != nil {
		return Document{}, e
	}
	var doc Document
	version := false
	var walk func(*yaml.Node, string, int) error
	walk = func(n *yaml.Node, key string, depth int) error {
		if depth > 16 {
			return problem(n, "policy nesting exceeds 16 levels")
		}
		if n.Anchor != "" || n.Kind == yaml.AliasNode {
			return problem(n, "YAML anchors and aliases are not allowed")
		}
		if isList(key) {
			if n.Kind != yaml.MappingNode {
				return problem(n, key+" requires replace: [...] or append: [...]")
			}
			if len(n.Content) != 2 || !strings.Contains("|replace|append|", "|"+n.Content[0].Value+"|") {
				return problem(n, key+" requires exactly one of replace or append")
			}
			items := n.Content[1]
			if items.Kind != yaml.SequenceNode {
				return problem(items, "list operation requires a sequence")
			}
			if len(items.Content) > 256 {
				return problem(items, "list exceeds 256 entries")
			}
			for _, item := range items.Content {
				if item.Kind != yaml.ScalarNode || item.Tag != "!!str" || item.Value == "" || len(item.Value) > 2048 || strings.ContainsAny(item.Value, "\x00\r\n") {
					return problem(item, "list entries must be nonempty single-line strings (max 2048 bytes)")
				}
				if e := validateItem(key, item); e != nil {
					return e
				}
			}
			doc.changes = append(doc.changes, change{key, n})
			return nil
		}
		allowed, branch := schema[key]
		if strings.HasPrefix(key, "rules.") && strings.Count(key, ".") == 1 {
			allowed = []string{"action", "enabled", "extra_match"}
			branch = true
		}
		if branch {
			if n.Kind != yaml.MappingNode || n.Tag != "!!map" {
				return problem(n, key+" must be a mapping")
			}
			seen := map[string]bool{}
			for i := 0; i < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Tag != "!!str" || k.Kind != yaml.ScalarNode {
					return problem(k, "mapping keys must be strings")
				}
				if seen[k.Value] {
					return problem(k, "duplicate key "+k.Value)
				}
				seen[k.Value] = true
				known := false
				for _, s := range allowed {
					known = known || s == k.Value
				}
				if !known {
					return problem(k, fmt.Sprintf("unknown key %q in %s; did you mean %q?", k.Value, location(key), suggest(k.Value, allowed)))
				}
				child := k.Value
				if key != "" {
					child = key + "." + child
				}
				if child == "version" {
					version = true
				}
				if e := walk(v, child, depth+1); e != nil {
					return e
				}
			}
			return nil
		}
		if n.Kind != yaml.ScalarNode {
			return problem(n, key+" must be a scalar")
		}
		if e := validateScalar(key, n); e != nil {
			return e
		}
		doc.changes = append(doc.changes, change{key, n})
		return nil
	}
	if e := walk(root.Content[0], "", 0); e != nil {
		return Document{}, e
	}
	if !version {
		return Document{}, fmt.Errorf("line 1: required version: 1 is missing")
	}
	return doc, nil
}
func location(k string) string {
	if k == "" {
		return "policy"
	}
	return k
}
func suggest(s string, values []string) string {
	values = append([]string(nil), values...)
	sort.Strings(values)
	best := ""
	score := int(^uint(0) >> 1)
	for _, v := range values {
		row := make([]int, len(v)+1)
		for i := range row {
			row[i] = i
		}
		for i, a := range s {
			prev := row[0]
			row[0] = i + 1
			for j, b := range v {
				old := row[j+1]
				cost := 0
				if a != b {
					cost = 1
				}
				row[j+1] = min(row[j]+1, row[j+1]+1, prev+cost)
				prev = old
			}
		}
		if row[len(v)] < score {
			score = row[len(v)]
			best = v
		}
	}
	return best
}
func validateScalar(k string, n *yaml.Node) error {
	v := n.Value
	switch {
	case k == "version" || k == "log.rotation.max_bytes" || k == "log.rotation.keep" || k == "state.retention_days":
		number, e := strconv.ParseInt(v, 10, 64)
		if n.Tag != "!!int" || e != nil || number < 1 {
			return problem(n, k+" must be a positive decimal integer")
		}
		if k == "version" && number != 1 {
			return problem(n, "unsupported version; expected 1")
		}
		if k == "log.rotation.keep" && number > 20 || k == "state.retention_days" && number > 3650 || k == "log.rotation.max_bytes" && number > 1<<30 {
			return problem(n, k+" exceeds its supported limit")
		}
	case k == "allow_project_loosening" || strings.HasSuffix(k, ".enabled"):
		if n.Tag != "!!bool" || v != "true" && v != "false" {
			return problem(n, k+" requires true or false")
		}
	default:
		if n.Tag != "!!str" || len(v) > 4096 || strings.ContainsAny(v, "\x00\r\n") {
			return problem(n, k+" must be a single-line string")
		}
		switch {
		case k == "fail_mode":
			if v != "open" && v != "closed" {
				return problem(n, "fail_mode must be open or closed")
			}
		case k == "profile":
			if v != "balanced" && v != "paranoid" {
				return problem(n, "profile must be balanced or paranoid")
			}
		case strings.HasSuffix(k, ".action"):
			if v != "allow" && v != "ask" && v != "deny" {
				return problem(n, "action must be allow, ask or deny")
			}
		case k == "log.path":
			if v == "" || v == "." || v == ".." || strings.HasSuffix(v, "/") || strings.HasSuffix(v, "\\") {
				return problem(n, "log.path must name a file")
			}
		}
	}
	return nil
}
func validateItem(k string, n *yaml.Node) error {
	v := n.Value
	switch {
	case k == "egress.allow_domains":
		if net.ParseIP(v) == nil {
			if v != strings.ToLower(v) || strings.ContainsAny(v, "/:@*?[] ") || strings.HasPrefix(v, ".") || strings.HasSuffix(v, ".") {
				return problem(n, "allow_domains requires exact lowercase host names, without URL, port or wildcard")
			}
			for _, part := range strings.Split(v, ".") {
				if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
					return problem(n, "invalid domain")
				}
				for _, ch := range part {
					if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
						return problem(n, "invalid domain")
					}
				}
			}
			if len(v) > 253 {
				return problem(n, "domain too long")
			}
		}
	case strings.HasSuffix(k, ".extra_match"):
		if _, e := regexp.Compile(v); e != nil {
			return problem(n, "invalid RE2 extra_match pattern: "+e.Error())
		}
	case k == "sources.bash.reader_commands":
		r := shellparse.Parse(v)
		if r.Unparseable || r.Uncertain || len(r.Commands) != 1 || r.Pipelines+r.Substitutions+r.Subshells+r.Heredocs > 0 || len(r.Operators) > 0 || len(r.Redirections) > 0 {
			return problem(n, "reader command must be one literal command prefix")
		}
	case k == "sources.mcp.trusted_servers":
		if strings.ContainsAny(v, "/\\*?[] \t") || strings.Contains(v, "__") {
			return problem(n, "trusted_servers requires exact MCP server segments")
		}
	default:
		if k == "sources.tools" || strings.Contains(k, "glob") || k == "secrets.paths" || k == "protected_writes" {
			for _, s := range strings.Split(v, "/") {
				if _, e := path.Match(s, ""); e != nil {
					return problem(n, "invalid glob: "+e.Error())
				}
			}
		}
	}
	return nil
}
