package install

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

// SettingsPath honors Claude Code's documented configuration directory override.
func SettingsPath() (string, error) {
	d := os.Getenv("CLAUDE_CONFIG_DIR")
	if d == "" {
		h, e := os.UserHomeDir()
		if e != nil {
			return "", e
		}
		d = filepath.Join(h, ".claude")
	}
	return filepath.Join(d, "settings.json"), nil
}

type receipt struct {
	Binary      string          `json:"binary"`
	Entries     map[string]any  `json:"entries"`
	HadHooks    bool            `json:"had_hooks"`
	HadSettings bool            `json:"had_settings"`
	EmptyEvents map[string]bool `json:"empty_events,omitempty"`
}

// HookEntries returns dedicated matcher groups, preserving unrelated groups.
func HookEntries(binary string) map[string]any {
	q := "'" + strings.ReplaceAll(filepath.ToSlash(binary), "'", "'\"'\"'") + "'"
	out := map[string]any{}
	for event, mode := range map[string]string{"PreToolUse": "pre", "PostToolUse": "post"} {
		out[event] = map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": q + " hook " + mode + " # taintwatch-managed-v1"}}}
	}
	out["UserPromptSubmit"] = map[string]any{"hooks": []any{map[string]any{"type": "command", "command": q + " hook prompt # taintwatch-managed-v1"}}}
	return out
}
func readObject(path string) (map[string]any, []byte, error) {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return map[string]any{}, nil, nil
	}
	if e != nil {
		return nil, nil, e
	}
	if !info.Mode().IsRegular() {
		return nil, nil, errors.New("settings must be a regular, non-symlink file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, nil, e
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(info, opened) {
		return nil, nil, errors.New("settings changed during read")
	}
	b, e := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if e != nil {
		return nil, nil, e
	}
	if len(b) > 8<<20 {
		return nil, nil, errors.New("settings exceed 8 MiB")
	}
	var v map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if e = dec.Decode(&v); e != nil {
		return nil, nil, e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF || v == nil {
		return nil, nil, errors.New("expected one JSON object")
	}
	return v, b, nil
}
func writeAtomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".taintwatch-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
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
	return os.Rename(name, path)
}
func encode(v any) []byte { b, _ := json.MarshalIndent(v, "", "  "); return append(b, '\n') }

// Change backs up settings and records only the exact entries it owns. A
// directory lock prevents concurrent Taintwatch installers; restart Claude first
// so its settings writer cannot race this external editor.
func Change(path, binary string, remove bool) (bool, string, error) {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return false, "", e
	}
	lock := path + ".taintwatch-lock"
	if e := os.Mkdir(lock, 0700); e != nil {
		return false, "", fmt.Errorf("settings installer locked: %w", e)
	}
	defer os.Remove(lock)
	v, original, e := readObject(path)
	if e != nil {
		return false, "", e
	}
	rp := path + ".taintwatch-install.json"
	rmap, _, e := readObject(rp)
	if e != nil {
		return false, "", e
	}
	var r receipt
	if len(rmap) > 0 {
		if e = json.Unmarshal(encode(rmap), &r); e != nil {
			return false, "", e
		}
	}
	hooks := map[string]any{}
	_, hadHooks := v["hooks"]
	if raw, ok := v["hooks"]; ok {
		var valid bool
		hooks, valid = raw.(map[string]any)
		if !valid {
			return false, "", errors.New("hooks must be an object")
		}
	}
	entries := HookEntries(binary)
	if remove {
		entries = r.Entries
		if len(entries) == 0 {
			return false, "", nil
		}
	} else if len(r.Entries) > 0 && r.Binary != binary {
		return false, "", errors.New("uninstall previous binary wiring before reinstalling at another path")
	}
	changed := false
	owned := map[string]any{}
	emptyEvents := r.EmptyEvents
	if emptyEvents == nil {
		emptyEvents = map[string]bool{}
	}
	for event, entry := range entries {
		list := []any{}
		if raw, ok := hooks[event]; ok {
			var valid bool
			list, valid = raw.([]any)
			if !valid {
				return false, "", fmt.Errorf("%s hooks must be an array", event)
			}
			if !remove && len(list) == 0 {
				emptyEvents[event] = true
			}
		}
		found := -1
		for i, x := range list {
			if reflect.DeepEqual(x, entry) {
				found = i
				break
			}
		}
		if remove {
			if found >= 0 {
				list = append(list[:found], list[found+1:]...)
				changed = true
			}
		} else {
			if found < 0 {
				list = append(list, entry)
				changed = true
				owned[event] = entry
			} else if old, ok := r.Entries[event]; ok && reflect.DeepEqual(old, entry) {
				owned[event] = entry
			}
		}
		if len(list) == 0 && !(remove && emptyEvents[event]) {
			delete(hooks, event)
		} else {
			hooks[event] = list
		}
	}
	if !changed {
		if remove {
			if e := os.Remove(rp); e != nil && !errors.Is(e, os.ErrNotExist) {
				return false, "", e
			}
		}
		return false, "", nil
	}
	// Persist ownership before settings, making an interrupted install reversible.
	if !remove {
		if len(r.Entries) > 0 {
			hadHooks = r.HadHooks
		}
		hadSettings := original != nil
		if len(r.Entries) > 0 {
			hadSettings = r.HadSettings
		}
		if e = writeAtomic(rp, encode(receipt{Binary: binary, Entries: owned, HadHooks: hadHooks, HadSettings: hadSettings, EmptyEvents: emptyEvents})); e != nil {
			return false, "", e
		}
	}
	backup := ""
	if original != nil {
		f, er := os.CreateTemp(filepath.Dir(path), "settings.json.taintwatch-backup-*")
		if er != nil {
			return false, "", er
		}
		backup = f.Name()
		er = f.Chmod(0600)
		if er == nil {
			_, er = f.Write(original)
		}
		if er == nil {
			er = f.Sync()
		}
		ce := f.Close()
		if er == nil {
			er = ce
		}
		if er != nil {
			return false, "", er
		}
	}
	if len(hooks) == 0 && !(remove && r.HadHooks) {
		delete(v, "hooks")
	} else {
		v["hooks"] = hooks
	}
	if remove && !r.HadSettings && len(v) == 0 {
		e = os.Remove(path)
	} else {
		e = writeAtomic(path, encode(v))
	}
	if e != nil {
		return false, backup, e
	}
	if remove {
		e = os.Remove(rp)
	}
	return true, backup, e
}

// Wired checks dedicated standalone groups without modifying the settings.
func Wired(path, binary string) bool {
	v, _, e := readObject(path)
	if e != nil {
		return false
	}
	h, ok := v["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for event, want := range HookEntries(binary) {
		found := false
		list, _ := h[event].([]any)
		for _, x := range list {
			if reflect.DeepEqual(x, want) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// PluginWired checks the distributed configuration, not delivery in a running
// Claude session. The latter still requires observing /hooks and real payloads.
func PluginWired(root string) bool {
	if info, e := os.Lstat(filepath.Join(root, "bin", "taintwatch-launcher")); e != nil || !info.Mode().IsRegular() {
		return false
	}
	v, _, e := readObject(filepath.Join(root, "hooks", "hooks.json"))
	if e != nil {
		return false
	}
	h, ok := v["hooks"].(map[string]any)
	if !ok {
		return false
	}
	for event, mode := range map[string]string{"PreToolUse": "pre", "PostToolUse": "post", "UserPromptSubmit": "prompt"} {
		want := map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": "TAINTWATCH_NO_BOOTSTRAP=1 sh \"${CLAUDE_PLUGIN_ROOT}/bin/taintwatch-launcher\" hook " + mode}}}
		if event == "UserPromptSubmit" {
			delete(want, "matcher")
		}
		found := false
		groups, _ := h[event].([]any)
		for _, group := range groups {
			if reflect.DeepEqual(group, want) {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
