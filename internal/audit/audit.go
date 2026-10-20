package audit

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

// Record is a redacted JSONL observation. A post hook's allow decision means that
// the completed call is not blocked; it is not a PreToolUse permission approval.
// StateKnown disambiguates a clean snapshot from an unavailable state on errors.
type Record struct {
	TS           time.Time `json:"ts"`
	Session      string    `json:"session"`
	Hook         string    `json:"hook"`
	Tool         string    `json:"tool"`
	Decision     string    `json:"decision"`
	Rule         string    `json:"rule"`
	Reason       string    `json:"reason"`
	Tainted      bool      `json:"tainted"`
	StateKnown   bool      `json:"state_known"`
	TaintSources []string  `json:"taint_sources"`
	InputSummary string    `json:"input_summary"`
	FailMode     string    `json:"fail_mode"`
}

// Sink abstracts secure storage so record construction can be tested separately.
type Sink interface{ AppendAudit([]byte) error }

var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bbearer\s+[^\s,;]+`),
	regexp.MustCompile(`(?i)(?:sk-[a-z0-9_-]{8,}|gh[pousr]_[a-z0-9_]{8,}|AKIA[A-Z0-9]{16})`),
	regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|password|authorization)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`),
}

// Redact strips common secret-shaped strings. Tool arguments and response bodies
// are deliberately omitted entirely, rather than relying on regex completeness.
func Redact(value string) string {
	for _, pattern := range secretPatterns {
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
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
	record.Session = Redact(state.SanitizeSessionID(record.Session))
	record.Hook = Redact(record.Hook)
	record.Tool = Redact(record.Tool)
	record.Decision = Redact(record.Decision)
	record.Rule = Redact(record.Rule)
	record.Reason = Redact(record.Reason)
	// Do not accept accidental raw-input summaries from callers at this stage.
	record.InputSummary = "tool arguments and response omitted"
	record.TaintSources = append([]string{}, record.TaintSources...)
	for i := range record.TaintSources {
		record.TaintSources[i] = Redact(record.TaintSources[i])
	}
	record.FailMode = Redact(record.FailMode)
	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode audit record: %w", err)
	}
	if err := sink.AppendAudit(b); err != nil {
		return fmt.Errorf("write audit record: %w", err)
	}
	return nil
}
