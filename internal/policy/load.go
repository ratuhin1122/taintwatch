package policy

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Ignored struct {
	Path   string `yaml:"path"`
	Origin string `yaml:"origin"`
	Reason string `yaml:"reason"`
}
type Effective struct {
	Config  Config
	Origins map[string]string
	Files   []string
	Ignored []Ignored
}
type Options struct {
	CWD, UserHome, UserFile, ProjectFile string
	NoUser, NoProject                    bool
}

// Load returns the last valid, guarded policy even on an error, so callers can
// apply a previously established fail_mode rather than reverting to open.
func Load(opts Options) (Effective, error) {
	c := Defaults()
	e := Effective{Config: c, Origins: map[string]string{}, Files: []string{}, Ignored: []Ignored{}}
	e.seedOrigins()
	var err error
	user := opts.UserFile
	if user == "" && !opts.NoUser {
		home := opts.UserHome
		if home == "" {
			home, err = os.UserHomeDir()
			if err != nil {
				return e, err
			}
		}
		user = filepath.Join(home, ".config", "taintwatch", "policy.yaml")
	}
	if !opts.NoUser {
		if err = e.readLayer(user, false); err != nil {
			return e, err
		}
	}
	if !opts.NoProject {
		cwd := opts.CWD
		if cwd == "" {
			cwd, err = os.Getwd()
			if err != nil {
				return e, err
			}
		}
		cwd, err = filepath.Abs(cwd)
		if err != nil {
			return e, err
		}
		project := opts.ProjectFile
		if project == "" {
			for dir := cwd; ; dir = filepath.Dir(dir) {
				p := filepath.Join(dir, ".taintwatch", "policy.yaml")
				if _, err := os.Lstat(p); err == nil {
					project = p
					break
				} else if !os.IsNotExist(err) {
					return e, fmt.Errorf("find project policy: %w", err)
				}
				if filepath.Dir(dir) == dir {
					break
				}
			}
		}
		if project != "" {
			if err = e.readLayer(project, true); err != nil {
				return e, err
			}
		}
	}
	for _, v := range []struct{ env, key string }{{"TAINTWATCH_AUDIT_MAX_BYTES", "log.rotation.max_bytes"}, {"TAINTWATCH_AUDIT_KEEP", "log.rotation.keep"}} {
		if raw := os.Getenv(v.env); raw != "" {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || n < 1 || v.env == "TAINTWATCH_AUDIT_KEEP" && n > 20 || v.env == "TAINTWATCH_AUDIT_MAX_BYTES" && n > 1<<30 {
				return e, fmt.Errorf("invalid %s", v.env)
			}
			e.setScalar(v.key, n)
			e.Origins[v.key] = "environment: " + v.env
		}
	}
	return e, nil
}

// Check validates a file without loading other layers or granting project trust.
func Check(file string) error { _, err := readDocument(file); return err }
func readDocument(file string) (Document, error) {
	f, err := openPolicy(file)
	if err != nil {
		return Document{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return Document{}, err
	}
	if !info.Mode().IsRegular() {
		return Document{}, fmt.Errorf("%s: policy must be a regular file", file)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return Document{}, err
	}
	d, err := Parse(b)
	if err != nil {
		return Document{}, fmt.Errorf("%s: %w", file, err)
	}
	return d, nil
}
func (e *Effective) readLayer(file string, project bool) error {
	absolute, err := filepath.Abs(file)
	if err != nil {
		return err
	}
	d, err := readDocument(absolute)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	e.Files = append(e.Files, absolute)
	for _, ch := range d.changes {
		e.apply(ch, fmt.Sprintf("%s:%d", absolute, ch.node.Line), project)
	}
	return nil
}
func (e *Effective) apply(ch change, origin string, project bool) {
	restricted := project && !e.Config.AllowProjectLoosening
	k := ch.key
	ignoredReasons := map[string]bool{}
	ignore := func(why string) {
		if !ignoredReasons[why] {
			e.Ignored = append(e.Ignored, Ignored{k, origin, why})
			ignoredReasons[why] = true
		}
	}
	if k == "allow_project_loosening" && project {
		ignore("only the user layer may grant project loosening")
		return
	}
	if isList(k) {
		oldOrigin := e.Origins[k]
		beforeIgnored := len(e.Ignored)
		old := e.list(k)
		next := []string{}
		if ch.node.Content[0].Value == "append" {
			next = append(next, old...)
		}
		for _, v := range ch.node.Content[1].Content {
			if !has(next, v.Value) {
				next = append(next, v.Value)
			}
		}
		permissive := k == "egress.allow_domains" || k == "sources.mcp.trusted_servers" || strings.HasSuffix(k, ".extra_match") && e.Config.Rules[strings.Split(k, ".")[1]].Action == "allow"
		if restricted {
			if permissive {
				safe := []string{}
				for _, v := range next {
					if has(old, v) {
						safe = append(safe, v)
					} else {
						ignore("project trust/allowlist addition ignored")
					}
				}
				next = safe
			} else {
				for _, v := range old {
					if !has(next, v) {
						next = append(next, v)
						ignore("project removal of a restriction ignored")
					}
				}
			}
		}
		oldOrigins := map[string]string{}
		for i, v := range old {
			oldOrigins[v] = e.Origins[fmt.Sprintf("%s[%d]", k, i)]
		}
		for key := range e.Origins {
			if strings.HasPrefix(key, k+"[") {
				delete(e.Origins, key)
			}
		}
		for i, v := range next {
			from := origin
			for _, node := range ch.node.Content[1].Content {
				if node.Value == v {
					from = origin[:strings.LastIndex(origin, ":")+1] + strconv.Itoa(node.Line)
					break
				}
			}
			if has(old, v) && (ch.node.Content[0].Value == "append" || restricted && !hasNode(ch.node.Content[1], v)) {
				from = oldOrigins[v]
			}
			e.Origins[fmt.Sprintf("%s[%d]", k, i)] = from
		}
		e.setList(k, next)
		e.Origins[k] = origin
		if restricted && reflect.DeepEqual(old, next) && len(e.Ignored) > beforeIgnored {
			e.Origins[k] = oldOrigin
		}
		return
	}
	old := e.scalar(k)
	var value any
	if ch.node.Tag == "!!bool" {
		value = ch.node.Value == "true"
	} else if ch.node.Tag == "!!int" {
		v, _ := strconv.ParseInt(ch.node.Value, 10, 64)
		value = v
	} else {
		value = ch.node.Value
	}
	if restricted && isLoosening(k, old, value) {
		ignore("project change cannot be proven restrictive")
		return
	}
	e.setScalar(k, value)
	e.Origins[k] = origin
}
func isLoosening(k string, old, next any) bool {
	if reflect.DeepEqual(old, next) {
		return false
	}
	switch k {
	case "version":
		return false
	case "fail_mode":
		return next == "open"
	case "profile":
		return next == "balanced"
	case "log.path":
		return true
	case "log.rotation.max_bytes", "log.rotation.keep", "state.retention_days":
		return next.(int64) < old.(int64)
	}
	if strings.HasSuffix(k, ".enabled") {
		return next == false
	}
	if strings.HasSuffix(k, ".action") {
		rank := map[string]int{"allow": 0, "ask": 1, "deny": 2}
		return rank[next.(string)] < rank[old.(string)]
	}
	return true
}
func has(ss []string, s string) bool {
	for _, v := range ss {
		if s == v {
			return true
		}
	}
	return false
}
func hasNode(n *yaml.Node, s string) bool {
	for _, v := range n.Content {
		if v.Value == s {
			return true
		}
	}
	return false
}
func (e *Effective) list(k string) []string {
	switch k {
	case "sources.tools":
		return e.Config.Sources.Tools
	case "sources.mcp.trusted_servers":
		return e.Config.Sources.MCP.TrustedServers
	case "sources.bash.reader_commands":
		return e.Config.Sources.Bash.ReaderCommands
	case "sources.read.taint_globs":
		return e.Config.Sources.Read.TaintGlobs
	case "sources.read.temp_paths":
		return e.Config.Sources.Read.TempPaths
	case "sources.read.downloaded_paths":
		return e.Config.Sources.Read.DownloadedPaths
	case "egress.allow_domains":
		return e.Config.Egress.AllowDomains
	case "secrets.paths":
		return e.Config.Secrets.Paths
	case "protected_writes":
		return e.Config.ProtectedWrites
	}
	return e.Config.Rules[strings.Split(k, ".")[1]].ExtraMatch
}
func (e *Effective) setList(k string, v []string) {
	switch k {
	case "sources.tools":
		e.Config.Sources.Tools = v
	case "sources.mcp.trusted_servers":
		e.Config.Sources.MCP.TrustedServers = v
	case "sources.bash.reader_commands":
		e.Config.Sources.Bash.ReaderCommands = v
	case "sources.read.taint_globs":
		e.Config.Sources.Read.TaintGlobs = v
	case "sources.read.temp_paths":
		e.Config.Sources.Read.TempPaths = v
	case "sources.read.downloaded_paths":
		e.Config.Sources.Read.DownloadedPaths = v
	case "egress.allow_domains":
		e.Config.Egress.AllowDomains = v
	case "secrets.paths":
		e.Config.Secrets.Paths = v
	case "protected_writes":
		e.Config.ProtectedWrites = v
	default:
		id := strings.Split(k, ".")[1]
		r := e.Config.Rules[id]
		r.ExtraMatch = v
		e.Config.Rules[id] = r
	}
}
func (e *Effective) scalar(k string) any {
	switch k {
	case "version":
		return int64(e.Config.Version)
	case "fail_mode":
		return e.Config.FailMode
	case "profile":
		return e.Config.Profile
	case "allow_project_loosening":
		return e.Config.AllowProjectLoosening
	case "log.path":
		return e.Config.Log.Path
	case "log.rotation.max_bytes":
		return e.Config.Log.Rotation.MaxBytes
	case "log.rotation.keep":
		return int64(e.Config.Log.Rotation.Keep)
	case "state.retention_days":
		return int64(e.Config.State.RetentionDays)
	}
	parts := strings.Split(k, ".")
	r := e.Config.Rules[parts[1]]
	if parts[2] == "enabled" {
		return r.Enabled
	}
	return r.Action
}
func (e *Effective) setScalar(k string, v any) {
	switch k {
	case "version":
		e.Config.Version = int(v.(int64))
	case "fail_mode":
		e.Config.FailMode = v.(string)
	case "profile":
		e.Config.Profile = v.(string)
	case "allow_project_loosening":
		e.Config.AllowProjectLoosening = v.(bool)
	case "log.path":
		e.Config.Log.Path = v.(string)
	case "log.rotation.max_bytes":
		e.Config.Log.Rotation.MaxBytes = v.(int64)
	case "log.rotation.keep":
		e.Config.Log.Rotation.Keep = int(v.(int64))
	case "state.retention_days":
		e.Config.State.RetentionDays = int(v.(int64))
	default:
		parts := strings.Split(k, ".")
		r := e.Config.Rules[parts[1]]
		if parts[2] == "enabled" {
			r.Enabled = v.(bool)
		} else {
			r.Action = v.(string)
		}
		e.Config.Rules[parts[1]] = r
	}
}
func (e *Effective) seedOrigins() {
	var n yaml.Node
	_ = n.Encode(e.Config)
	var walk func(*yaml.Node, string)
	walk = func(n *yaml.Node, k string) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				child := n.Content[i].Value
				if k != "" {
					child = k + "." + child
				}
				walk(n.Content[i+1], child)
			}
		} else {
			e.Origins[k] = "built-in"
			if n.Kind == yaml.SequenceNode {
				for i := range n.Content {
					e.Origins[fmt.Sprintf("%s[%d]", k, i)] = "built-in"
				}
			}
		}
	}
	walk(&n, "")
}

// Show emits effective values with per-leaf and per-list-item origin comments.
func (e Effective) Show(w io.Writer) error {
	var n yaml.Node
	if err := n.Encode(e.Config); err != nil {
		return err
	}
	var walk func(*yaml.Node, string)
	walk = func(n *yaml.Node, k string) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i < len(n.Content); i += 2 {
				child := n.Content[i].Value
				if k != "" {
					child = k + "." + child
				}
				walk(n.Content[i+1], child)
			}
		} else {
			n.LineComment = "origin: " + e.Origins[k]
			if n.Kind == yaml.SequenceNode {
				for i, v := range n.Content {
					v.LineComment = "origin: " + e.Origins[fmt.Sprintf("%s[%d]", k, i)]
				}
				sequence := *n
				sequence.HeadComment = ""
				sequence.LineComment = ""
				*n = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", HeadComment: "origin: " + e.Origins[k], Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "replace"}, &sequence}}
			}
		}
	}
	walk(&n, "")
	enc := yaml.NewEncoder(w)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		_ = enc.Close()
		return err
	}
	return enc.Close()
}
