package eval

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/hookio"
)

const MaxFileBytes = 4 << 20
const maxCorpusBytes = 64 << 20

// These types describe corpus documents, not the Claude Code wire protocol.
// Payload decoding stays in hookio, including event/argument validation.
type Scenario struct {
	SchemaVersion   int        `json:"schema_version"`
	ID              string     `json:"id"`
	Category        string     `json:"category"`
	Description     string     `json:"description"`
	Provenance      Provenance `json:"provenance"`
	License         string     `json:"license"`
	KnownMiss       bool       `json:"known_miss"`
	KnownMissReason string     `json:"known_miss_reason,omitempty"`
	Target          string     `json:"target"`
	Steps           []Step     `json:"steps"`
}
type Provenance struct {
	Kind        string `json:"kind"`
	Author      string `json:"author"`
	Source      string `json:"source"`
	Attribution string `json:"attribution"`
}
type Step struct {
	ID      string          `json:"id"`
	Event   string          `json:"event"`
	Payload json.RawMessage `json:"payload"`
	Expect  *Expectation    `json:"expect,omitempty"`
}
type Expectation struct {
	Decision string `json:"decision"`
	Rule     string `json:"rule,omitempty"`
}
type Summary struct{ Files, Attacks, Benign, Steps, Expectations, KnownMisses int }

var slug = regexp.MustCompile(`^[a-z][a-z0-9-]{1,62}$`)
var ruleID = regexp.MustCompile(`^(?:TW[0-9]{3}|default\.allow)$`)

// Decode strictly validates corpus syntax. Duplicate keys anywhere (including
// payloads) are errors; unknown corpus keys are errors, but hookio retains its
// documented forward-compatible treatment of unknown envelope/tool fields.
func Decode(r io.Reader) (Scenario, error) {
	var s Scenario
	b, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return s, fmt.Errorf("read scenario: %w", err)
	}
	if len(b) > MaxFileBytes {
		return s, errors.New("scenario exceeds 4 MiB")
	}
	if err = uniqueKeys(b); err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return s, fmt.Errorf("scenario JSON: %w", err)
	}
	if d.Decode(new(any)) != io.EOF {
		return s, errors.New("expected exactly one scenario object")
	}
	if err = check(s); err != nil {
		return s, err
	}
	return s, nil
}

func uniqueKeys(b []byte) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	type frame struct {
		keys map[string]bool
		key  bool
	}
	var stack []frame
	for {
		v, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("invalid JSON: %w", err)
		}
		if delim, ok := v.(json.Delim); ok {
			if delim == '}' || delim == ']' {
				stack = stack[:len(stack)-1]
				continue
			}
			if len(stack) >= 64 {
				return errors.New("JSON nesting exceeds 64")
			}
			if len(stack) > 0 && stack[len(stack)-1].keys != nil {
				stack[len(stack)-1].key = true
			}
			f := frame{}
			if delim == '{' {
				f.keys = map[string]bool{}
				f.key = true
			}
			stack = append(stack, f)
			continue
		}
		if len(stack) > 0 {
			f := &stack[len(stack)-1]
			if f.keys != nil {
				if f.key {
					k := v.(string)
					if f.keys[k] {
						return fmt.Errorf("duplicate JSON key at byte %d", d.InputOffset())
					}
					f.keys[k] = true
				}
				f.key = !f.key
			}
		}
	}
}
func required(s string, n int) bool { return strings.TrimSpace(s) != "" && len(s) <= n }
func check(s Scenario) error {
	fail := func(msg string) error { return errors.New(msg) }
	if s.SchemaVersion != 1 {
		return fail("schema_version must be 1")
	}
	if !slug.MatchString(s.ID) || !slug.MatchString(s.Category) {
		return fail("id/category must be lowercase slugs of 2–63 characters")
	}
	if !required(s.Description, 2000) {
		return fail("description is required (at most 2000 bytes)")
	}
	p := s.Provenance
	if (p.Kind != "original" && p.Kind != "permissive-derived") || !required(p.Author, 200) || !required(p.Source, 2000) || !required(p.Attribution, 2000) {
		return fail("provenance requires kind original|permissive-derived, author, source, and attribution")
	}
	if p.Kind == "permissive-derived" && !strings.HasPrefix(p.Source, "https://") {
		return fail("derived provenance.source must be an https source URL")
	}
	switch s.License {
	case "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "CC0-1.0":
	default:
		return fail("license must be an approved permissive SPDX identifier")
	}
	if s.Target != "M3" && s.Target != "M4" {
		return fail("target must be M3 or M4")
	}
	if s.KnownMiss && !required(s.KnownMissReason, 2000) || !s.KnownMiss && s.KnownMissReason != "" {
		return fail("known_miss requires a nonempty known_miss_reason; omit the reason otherwise")
	}
	if s.Target == "M4" && !s.KnownMiss {
		return fail("M4 targets must currently be marked known_miss")
	}
	if len(s.Steps) < 2 || len(s.Steps) > 256 {
		return fail("steps must contain 2–256 ordered events")
	}
	ids := map[string]bool{}
	post, scored, afterPost, adverse := false, false, false, false
	for i, step := range s.Steps {
		prefix := fmt.Sprintf("step %d: ", i+1)
		if !slug.MatchString(step.ID) || ids[step.ID] {
			return fail(prefix + "step id must be a unique slug")
		}
		ids[step.ID] = true
		var envelope hookio.ToolEventInput
		switch step.Event {
		case "PreToolUse":
			in, err := hookio.DecodePreToolUse(bytes.NewReader(step.Payload))
			if err != nil {
				return fmt.Errorf("%sinvalid PreToolUse envelope: %w", prefix, err)
			}
			envelope = in.ToolEventInput
		case "PostToolUse":
			in, err := hookio.DecodePostToolUse(bytes.NewReader(step.Payload))
			if err != nil {
				return fmt.Errorf("%sinvalid PostToolUse envelope: %w", prefix, err)
			}
			envelope = in.ToolEventInput
			post = true
			if step.Expect != nil {
				return fail(prefix + "expect is permitted only on PreToolUse action requests")
			}
		default:
			return fail(prefix + "event must be PreToolUse or PostToolUse")
		}
		if envelope.SessionID != s.ID || envelope.CWD != "/workspace/project" {
			return fail(prefix + "payload must use scenario id as session_id and canonical cwd /workspace/project")
		}
		if _, err := envelope.SourceArguments(); err != nil {
			return fmt.Errorf("%sinvalid tool arguments: %w", prefix, err)
		}
		if e := step.Expect; e != nil {
			if e.Decision != "allow" && e.Decision != "ask" && e.Decision != "deny" {
				return fail(prefix + "expect.decision must be allow, ask, or deny")
			}
			if e.Rule != "" && !ruleID.MatchString(e.Rule) {
				return fail(prefix + "expect.rule must be TWnnn or default.allow")
			}
			if e.Rule == "default.allow" && e.Decision != "allow" {
				return fail(prefix + "default.allow requires decision allow")
			}
			scored = true
			afterPost = afterPost || post
			adverse = adverse || e.Decision != "allow"
		}
	}
	if !post || !scored || !afterPost {
		return fail("sequence requires a PostToolUse result and an expected PreToolUse action after a result")
	}
	if s.KnownMiss && !adverse {
		return fail("known misses must retain an ask/deny security expectation")
	}
	return nil
}

// Validate walks a corpus root read-only. It does not load operator policy,
// create state, replay hooks, run shell commands, or contact any endpoint.
func Validate(root string) (Summary, error) {
	var sum Summary
	info, err := os.Lstat(root)
	if err != nil {
		return sum, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return sum, errors.New("corpus root must be a real directory")
	}
	seen := map[string]bool{}
	total := int64(0)
	var issues []error
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if len(issues) >= 64 {
			return errors.New("stopped after 64 validation errors")
		}
		bad := func(msg string) {
			rel, _ := filepath.Rel(root, path)
			issues = append(issues, fmt.Errorf("%s: %s", filepath.ToSlash(rel), msg))
		}
		if walkErr != nil {
			bad("cannot inspect corpus entry")
			return nil
		}
		if path == root {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		if d.Type()&os.ModeSymlink != 0 {
			bad("symlinks are not permitted")
			return nil
		}
		if parts[0] != "attacks" && parts[0] != "benign" {
			if len(parts) == 1 && !d.IsDir() && (parts[0] == "README.md" || parts[0] == "LICENSE") {
				return nil
			}
			bad("expected attacks/ or benign/ scenarios")
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if len(parts) < 2 || filepath.Ext(path) != ".json" || !d.Type().IsRegular() {
			bad("expected a regular .json scenario file")
			return nil
		}
		sum.Files++
		if sum.Files > 10000 {
			return errors.New("corpus exceeds 10000 files")
		}
		f, err := os.Open(path)
		if err != nil {
			bad("cannot read scenario")
			return nil
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			bad("cannot stat scenario")
			return nil
		}
		total += st.Size()
		if total > maxCorpusBytes {
			f.Close()
			return errors.New("corpus exceeds 64 MiB")
		}
		s, err := Decode(f)
		f.Close()
		if err != nil {
			bad(err.Error())
			return nil
		}
		if filepath.Base(path) != s.ID+".json" {
			bad("filename must be <id>.json")
		}
		if seen[s.ID] {
			bad("duplicate scenario id")
		}
		seen[s.ID] = true
		if parts[0] == "benign" && s.KnownMiss {
			bad("known_miss is reserved for attacks")
		}
		adverse := false
		for _, step := range s.Steps {
			if step.Expect != nil && step.Expect.Decision != "allow" {
				adverse = true
			}
		}
		if parts[0] == "attacks" && !adverse {
			bad("attack must retain an ask/deny action expectation")
		}
		if parts[0] == "benign" && adverse {
			bad("benign action expectations must be allow; do not encode current false positives as desired behavior")
		}
		if parts[0] == "attacks" {
			sum.Attacks++
		} else {
			sum.Benign++
		}
		if s.KnownMiss {
			sum.KnownMisses++
		}
		sum.Steps += len(s.Steps)
		for _, step := range s.Steps {
			if step.Expect != nil {
				sum.Expectations++
			}
		}
		return nil
	})
	if err != nil {
		issues = append(issues, err)
	}
	if sum.Attacks == 0 || sum.Benign == 0 {
		issues = append(issues, errors.New("corpus requires at least one valid attack and one valid benign scenario"))
	}
	return sum, errors.Join(issues...)
}
