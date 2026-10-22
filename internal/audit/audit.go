package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/detect/encoded"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/detect/pasted"
	"github.com/ratuhin1122/taintwatch/internal/rules"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

// DecodeRecord reads one stored audit object and reapplies metadata redaction.
// Tool payloads/old raw input summaries are never recovered from unknown fields.
func DecodeRecord(data []byte) (Record, error) {
	var r Record
	b := bytes.TrimSpace(data)
	if len(b) == 0 || len(b) > 64<<10 || b[0] != '{' {
		return r, fmt.Errorf("invalid audit object")
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("invalid audit object")
	}
	return sanitize(r), nil
}

// Record is a redacted JSONL observation. A post hook's allow decision means that
// the completed call is not blocked; it is not a PreToolUse permission approval.
// StateKnown disambiguates a clean snapshot from an unavailable state on errors.
type Record struct {
	TS             time.Time       `json:"ts"`
	Session        string          `json:"session"`
	Hook           string          `json:"hook"`
	Tool           string          `json:"tool"`
	Decision       string          `json:"decision"`
	Rule           string          `json:"rule"`
	Reason         string          `json:"reason"`
	Who            string          `json:"who,omitempty"`
	Tainted        bool            `json:"tainted"`
	StateKnown     bool            `json:"state_known"`
	TaintSources   []string        `json:"taint_sources"`
	InputSummary   string          `json:"input_summary"`
	FailMode       string          `json:"fail_mode"`
	Evidence       []string        `json:"evidence,omitempty"`
	PolicyWarnings []string        `json:"policy_warnings,omitempty"`
	Hidden         *hidden.Report  `json:"hidden,omitempty"`
	Encoded        *encoded.Report `json:"encoded,omitempty"`
	Pasted         *pasted.Report  `json:"pasted,omitempty"`
	Replay         *rules.Snapshot `json:"replay,omitempty"`
}

// Sink abstracts secure storage so record construction can be tested separately.
type Sink interface{ AppendAudit([]byte) error }

var secretPatterns = []struct {
	kind    string
	pattern *regexp.Regexp
}{
	{"private-key", regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)`)},
	{"bearer", regexp.MustCompile(`(?i)\bbearer\s+[^\s,;"']+`)},
	{"aws", regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)},
	{"github", regexp.MustCompile(`(?:gh[pousr]_[a-zA-Z0-9_]{8,}|github_pat_[a-zA-Z0-9_]{8,})`)},
	{"api-key", regexp.MustCompile(`sk-[a-zA-Z0-9_-]{8,}`)},
}
var assignmentPattern = regexp.MustCompile(`(?i)(["']?\b[a-z0-9_.-]*(?:password|secret|token|key)[a-z0-9_.-]*["']?\s*[:=]\s*)("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;]+)`)

// Redact strips common secret-shaped strings. Tool arguments and response bodies
// are deliberately omitted entirely, rather than relying on regex completeness.
func Redact(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.pattern.ReplaceAllString(value, "[REDACTED:"+pattern.kind+"]")
	}
	value = assignmentPattern.ReplaceAllStringFunc(value, func(s string) string {
		m := assignmentPattern.FindStringSubmatch(s)
		v := strings.Trim(m[2], "\"'")
		if strings.HasPrefix(v, "[REDACTED:") && strings.HasSuffix(v, "]") && strings.Count(v, "[") == 1 && !strings.Contains(v, " ") {
			return s
		}
		return m[1] + "[REDACTED:credential]"
	})
	if len(value) > 1024 {
		value = value[:1024] + "[TRUNCATED]"
	}
	return value
}

// Write encodes an audit record, never a Claude Code hook payload.
func Write(sink Sink, record Record) error {
	if record.TS.IsZero() {
		record.TS = time.Now().UTC()
	}
	record.Session = state.SanitizeSessionID(record.Session)
	record = sanitize(record)
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	if err := sink.AppendAudit(b); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}
func sanitize(record Record) Record {
	if record.Replay != nil {
		s := *record.Replay
		s.Fingerprint = Redact(s.Fingerprint)
		if s.Matches != nil {
			s.Matches = append([]string{}, s.Matches...)
		}
		for i := range s.Matches {
			s.Matches[i] = Redact(s.Matches[i])
		}
		record.Replay = &s
	}
	if record.Hidden != nil {
		h := *record.Hidden
		h.Findings = append([]hidden.Finding(nil), h.Findings...)
		for i := range h.Findings {
			h.Findings[i].Type = hidden.Visible(Redact(h.Findings[i].Type))
			h.Findings[i].Excerpt = hidden.Visible(Redact(h.Findings[i].Excerpt))
		}
		record.Hidden = &h
	}
	if record.Encoded != nil {
		e := *record.Encoded
		e.Findings = append([]encoded.Finding(nil), e.Findings...)
		for i := range e.Findings {
			e.Findings[i].Type = hidden.Visible(Redact(e.Findings[i].Type))
			e.Findings[i].Encoding = hidden.Visible(Redact(e.Findings[i].Encoding))
		}
		record.Encoded = &e
	}
	record.PolicyWarnings = append([]string(nil), record.PolicyWarnings...)
	for i := range record.PolicyWarnings {
		record.PolicyWarnings[i] = Redact(record.PolicyWarnings[i])
	}
	record.Session = Redact(record.Session)
	record.Hook = Redact(record.Hook)
	record.Tool = Redact(record.Tool)
	record.Decision = Redact(record.Decision)
	record.Rule = Redact(record.Rule)
	record.Reason = Redact(record.Reason)
	record.Who = Redact(record.Who)
	// Do not accept accidental raw-input summaries from callers at this stage.
	record.InputSummary = "tool arguments and response omitted"
	if record.Hook == "UserPromptSubmit" {
		record.InputSummary = "prompt content omitted"
	}
	record.TaintSources = append([]string{}, record.TaintSources...)
	for i := range record.TaintSources {
		record.TaintSources[i] = Redact(record.TaintSources[i])
	}
	record.FailMode = Redact(record.FailMode)
	record.Evidence = append([]string(nil), record.Evidence...)
	for i := range record.Evidence {
		record.Evidence[i] = Redact(record.Evidence[i])
	}
	return record
}
