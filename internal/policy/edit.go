package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// UserEdit contains a review proposal. Commit checks that the reviewed
// original has not changed; it never loads or writes a repository policy.
type UserEdit struct {
	Path          string
	Before, After []byte
}

func UserPath() (string, error) {
	h, e := os.UserHomeDir()
	if e != nil {
		return "", e
	}
	return filepath.Join(h, ".config", "taintwatch", "policy.yaml"), nil
}
func readEditFile(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("user policy must be a real regular file")
	}
	f, e := openPolicy(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil {
		return nil, e
	}
	if len(b) > MaxBytes {
		return nil, errors.New("policy exceeds 1 MiB")
	}
	return b, nil
}

// PrepareUserEdit creates an exact host or canonical file exception proposal.
// Domain removals may remove a built-in host via an explicit user replace list.
func PrepareUserEdit(kind, value string, remove bool) (UserEdit, error) {
	path, e := UserPath()
	if e != nil {
		return UserEdit{}, e
	}
	before, e := readEditFile(path)
	if e != nil {
		return UserEdit{}, e
	}
	loaded, e := Load(Options{NoProject: true})
	if e != nil {
		return UserEdit{}, e
	}
	key := "egress.allow_domains"
	items := loaded.Config.Egress.AllowDomains
	switch kind {
	case "domain":
		value = strings.ToLower(value)
	case "path":
		key = "secrets.allow_paths"
		items = loaded.Config.Secrets.AllowPaths
		if !filepath.IsAbs(value) {
			cwd, err := os.Getwd()
			if err != nil {
				return UserEdit{}, err
			}
			value = cwd + string(os.PathSeparator) + value
		}
		if !remove {
			value, e = filepath.EvalSymlinks(value)
			if e != nil {
				return UserEdit{}, fmt.Errorf("path must resolve to an existing file: %w", e)
			}
			info, e := os.Stat(value)
			if e != nil || !info.Mode().IsRegular() {
				return UserEdit{}, errors.New("path exception requires a regular file")
			}
		} else {
			if resolved, err := filepath.EvalSymlinks(value); err == nil {
				value = resolved
			} else {
				value = filepath.Clean(value)
			}
		}
	default:
		return UserEdit{}, errors.New("expected domain or path")
	}
	n := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
	if e := validateItem(key, &n); e != nil {
		return UserEdit{}, e
	}
	next := []string{}
	found := false
	for _, v := range items {
		if v == value {
			found = true
			if remove {
				continue
			}
		}
		next = append(next, v)
	}
	if found == !remove {
		return UserEdit{path, before, before}, nil
	}
	if !remove {
		next = append(next, value)
	}
	var document yaml.Node
	if before == nil {
		if e = yaml.Unmarshal([]byte("version: 1\n"), &document); e != nil {
			return UserEdit{}, e
		}
	} else {
		if _, e = Parse(before); e != nil {
			return UserEdit{}, e
		}
		if e = yaml.Unmarshal(before, &document); e != nil {
			return UserEdit{}, e
		}
	}
	var list yaml.Node
	if e = list.Encode(map[string][]string{"replace": next}); e != nil {
		return UserEdit{}, e
	}
	parts := strings.Split(key, ".")
	parent := document.Content[0]
	for _, part := range parts[:len(parts)-1] {
		var child *yaml.Node
		for i := 0; i < len(parent.Content); i += 2 {
			if parent.Content[i].Value == part {
				child = parent.Content[i+1]
				break
			}
		}
		if child == nil {
			child = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: part}, child)
		}
		parent = child
	}
	leaf := parts[len(parts)-1]
	replaced := false
	for i := 0; i < len(parent.Content); i += 2 {
		if parent.Content[i].Value == leaf {
			list.HeadComment = parent.Content[i+1].HeadComment
			parent.Content[i+1] = &list
			replaced = true
			break
		}
	}
	if !replaced {
		parent.Content = append(parent.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: leaf}, &list)
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if e = enc.Encode(&document); e != nil {
		return UserEdit{}, e
	}
	if e = enc.Close(); e != nil {
		return UserEdit{}, e
	}
	if _, e = Parse(out.Bytes()); e != nil {
		return UserEdit{}, e
	}
	return UserEdit{path, before, out.Bytes()}, nil
}
func (p UserEdit) Changed() bool { return !bytes.Equal(p.Before, p.After) }

// Diff shows the entire small policy replacement so no edited line is hidden.
func (p UserEdit) Diff() string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s (before)\n+++ %s (after)\n@@ complete user policy @@\n", p.Path, p.Path)
	for _, v := range []struct {
		prefix string
		data   []byte
	}{{"-", p.Before}, {"+", p.After}} {
		for _, line := range strings.Split(strings.TrimSuffix(string(v.data), "\n"), "\n") {
			if len(v.data) > 0 {
				fmt.Fprintln(&b, v.prefix+line)
			}
		}
	}
	return b.String()
}
func writePolicyAtomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".policy-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}

// Commit returns the backup path, or an error without overwriting concurrent edits.
func (p UserEdit) Commit() (string, error) {
	if !p.Changed() {
		return "", nil
	}
	if _, e := Parse(p.After); e != nil {
		return "", e
	}
	dir := filepath.Dir(p.Path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", e
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("policy directory must be a real directory")
	}
	if e = os.Chmod(dir, 0700); e != nil {
		return "", e
	}
	lock := p.Path + ".lock"
	if e = os.Mkdir(lock, 0700); e != nil {
		return "", fmt.Errorf("policy edit locked: %w", e)
	}
	defer os.Remove(lock)
	current, e := readEditFile(p.Path)
	if e != nil {
		return "", e
	}
	if !bytes.Equal(current, p.Before) {
		return "", errors.New("user policy changed after preview; run again and review the new diff")
	}
	backup := ""
	if current != nil {
		f, e := os.CreateTemp(dir, "policy.yaml.backup-*")
		if e != nil {
			return "", e
		}
		backup = f.Name()
		e = f.Chmod(0600)
		if e == nil {
			_, e = f.Write(current)
		}
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
		if e != nil {
			return "", e
		}
	}
	return backup, writePolicyAtomic(p.Path, p.After)
}
