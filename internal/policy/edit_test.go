package policy

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func editHome(t *testing.T) string {
	t.Helper()
	h := t.TempDir()
	t.Setenv("HOME", h)
	t.Setenv("USERPROFILE", h)
	t.Setenv("TAINTWATCH_AUDIT_MAX_BYTES", "")
	t.Setenv("TAINTWATCH_AUDIT_KEEP", "")
	return h
}
func TestUserEdits(t *testing.T) {
	h := editHome(t)
	p := filepath.Join(h, ".config", "taintwatch", "policy.yaml")
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	initial := []byte("# retain this comment\nversion: 1\nprofile: paranoid\n")
	if e := os.WriteFile(p, initial, 0600); e != nil {
		t.Fatal(e)
	}
	edit, e := PrepareUserEdit("domain", "EXAMPLE.COM", false)
	if e != nil || !edit.Changed() || !strings.Contains(edit.Diff(), "+  allow_domains:") {
		t.Fatal(e, edit.Diff())
	}
	b, _ := os.ReadFile(p)
	if !bytes.Equal(b, initial) {
		t.Fatal("preview changed file")
	}
	backup, e := edit.Commit()
	if e != nil {
		t.Fatal(e)
	}
	b, _ = os.ReadFile(backup)
	if !bytes.Equal(b, initial) {
		t.Fatal("backup changed")
	}
	loaded, e := Load(Options{NoProject: true})
	if e != nil || loaded.Config.Profile != "paranoid" || !has(loaded.Config.Egress.AllowDomains, "example.com") {
		t.Fatal(loaded, e)
	}
	again, e := PrepareUserEdit("domain", "example.com", false)
	if e != nil || again.Changed() {
		t.Fatal("not idempotent", e)
	}
	remove, e := PrepareUserEdit("domain", "github.com", true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = remove.Commit(); e != nil {
		t.Fatal(e)
	}
	loaded, e = Load(Options{NoProject: true})
	if e != nil || has(loaded.Config.Egress.AllowDomains, "github.com") {
		t.Fatal("builtin removal failed", e)
	}
	b, _ = os.ReadFile(p)
	if !strings.Contains(string(b), "retain this comment") {
		t.Fatal("comment lost")
	}
	file := filepath.Join(h, ".env")
	if e = os.WriteFile(file, []byte("private"), 0600); e != nil {
		t.Fatal(e)
	}
	edit, e = PrepareUserEdit("path", file, false)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = edit.Commit(); e != nil {
		t.Fatal(e)
	}
	loaded, e = Load(Options{NoProject: true})
	canonical, resolveErr := filepath.EvalSymlinks(file)
	if e != nil || resolveErr != nil || !has(loaded.Config.Secrets.AllowPaths, canonical) {
		t.Fatal("path missing", e)
	}
	if e = os.Remove(file); e != nil {
		t.Fatal(e)
	}
	edit, e = PrepareUserEdit("path", canonical, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = edit.Commit(); e != nil {
		t.Fatal(e)
	}
	loaded, e = Load(Options{NoProject: true})
	if e != nil || len(loaded.Config.Secrets.AllowPaths) != 0 {
		t.Fatal("deleted exception not removed", e)
	}
}
func TestEditRejectsInvalidAndConcurrent(t *testing.T) {
	h := editHome(t)
	for _, host := range []string{"https://evil.example", "*.example.com", "evil.example:443", "a\nb"} {
		if _, e := PrepareUserEdit("domain", host, false); e == nil {
			t.Fatal(host)
		}
	}
	if _, e := PrepareUserEdit("path", filepath.Join(h, "missing"), false); e == nil {
		t.Fatal("accepted missing file")
	}
	edit, e := PrepareUserEdit("domain", "example.com", false)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Dir(edit.Path), 0700); e != nil {
		t.Fatal(e)
	}
	original := []byte("version: 1\nprofile: paranoid\n")
	if e = os.WriteFile(edit.Path, original, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = edit.Commit(); e == nil {
		t.Fatal("overwrote concurrent edit")
	}
	b, _ := os.ReadFile(edit.Path)
	if !bytes.Equal(b, original) {
		t.Fatal("lost edit")
	}
}
func TestProjectCannotAddPathException(t *testing.T) {
	h := editHome(t)
	project := filepath.Join(h, "project.yaml")
	file := filepath.Join(h, ".env")
	var s strings.Builder // Quote paths portably through yaml encoding.
	s.WriteString("version: 1\nsecrets:\n  allow_paths:\n    append:\n")
	s.WriteString("      - " + singleYAML(file) + "\n")
	if e := os.WriteFile(project, []byte(s.String()), 0600); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(Options{ProjectFile: project, CWD: h})
	if e != nil || len(loaded.Config.Secrets.AllowPaths) != 0 || len(loaded.Ignored) != 1 {
		t.Fatal(loaded, e)
	}
}
func singleYAML(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
