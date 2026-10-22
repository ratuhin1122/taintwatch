package explain

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

// text keeps metadata on one terminal line; JSON output is escaped by encoding/json.
func text(s string) string { q := strconv.Quote(audit.Redact(s)); return q[1 : len(q)-1] }
func sources(ss []string) string {
	if len(ss) == 0 {
		return "unspecified"
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = text(s)
	}
	return strings.Join(out, ", ")
}

// Render describes recorded decisions, not a replay of commands or file contents.
func Render(w io.Writer, h audit.History, asJSON bool) error {
	if asJSON {
		return json.NewEncoder(w).Encode(h)
	}
	if h.Session == "" {
		_, e := fmt.Fprintln(w, "No recorded decisions yet.")
		return e
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Session %s — %d recent decision(s)\n", text(h.Session), len(h.Records))
	if len(h.Records) == 0 {
		fmt.Fprintln(&b, "No retained decisions for this session.")
	}
	for i := len(h.Records) - 1; i >= 0; i-- {
		r := h.Records[i]
		label := map[string]string{"ask": "Asked for approval", "allow": "No Taintwatch restriction", "deny": "Denied"}[r.Decision]
		if label == "" {
			label = "Recorded " + text(r.Decision)
		}
		if r.Hook == "PostToolUse" && r.Decision == "allow" {
			label = "Recorded completed tool call"
		}
		if r.Hook == "UserPromptSubmit" {
			label = "Recorded prompt telemetry"
		}
		fmt.Fprintf(&b, "\n%s UTC — %s: %s [%s]\n", r.TS.UTC().Format("2006-01-02 15:04:05"), label, text(r.Tool), text(r.Rule))
		fmt.Fprintf(&b, "Why: %s\n", text(r.Reason))
		if r.Hidden != nil {
			for _, f := range r.Hidden.Findings {
				fmt.Fprintf(&b, "Content hint (informational): %s; count=%d; excerpt=%s\n", text(hidden.Visible(f.Type)), f.Count, text(hidden.Visible(f.Excerpt)))
			}
			if r.Hidden.Truncated {
				fmt.Fprintf(&b, "Content scan: prefix only (%d bytes); response was truncated for scanning.\n", r.Hidden.BytesScanned)
			}
		}
		if r.Pasted != nil {
			fmt.Fprintf(&b, "Pasted-content hints (informational): fenced blocks=%d; log-like lines=%d; long log=%t.\n", r.Pasted.FencedBlocks, r.Pasted.LogLines, r.Pasted.LongLog)
			if r.Pasted.Truncated {
				fmt.Fprintf(&b, "Pasted-content scan: prefix only (%d bytes).\n", r.Pasted.BytesScanned)
			}
		}
		if r.Hook == "UserPromptSubmit" {
			fmt.Fprintln(&b, "Taint: unchanged (prompt telemetry only).")
		} else if !r.StateKnown {
			fmt.Fprintln(&b, "Taint: unknown (state was unavailable).")
		} else if r.Tainted {
			fmt.Fprintf(&b, "Taint: yes; sources: %s.\n", sources(r.TaintSources))
		} else {
			fmt.Fprintln(&b, "Taint: no.")
		}
		if r.Decision == "ask" {
			fmt.Fprintln(&b, "Next: approve once in Claude Code if you trust this action.")
			if r.Rule == "TW002" {
				fmt.Fprintln(&b, "For repeated access, review a permanent exception with taintwatch allow domain HOST.")
			}
			if r.Tainted {
				fmt.Fprintln(&b, "After reviewing the untrusted content, explicitly clear with taintwatch clear --session ID --reason TEXT.")
			}
		}
	}
	fmt.Fprintf(&b, "\nAsks in retained history: %d (older rotated records may have expired).\n", h.Asks)
	_, e := io.WriteString(w, b.String())
	return e
}

// Status reports current persisted taint separately from historical decisions.
func Status(w io.Writer, s state.Session, known bool, h audit.History) error {
	return StatusWithPolicy(w, s, known, h, nil)
}
func StatusWithPolicy(w io.Writer, s state.Session, known bool, h audit.History, files []string) error {
	var b strings.Builder
	if h.Session == "" && s.ID == "" {
		fmt.Fprintln(&b, "No session found.")
	} else {
		id := h.Session
		if id == "" {
			id = state.SanitizeSessionID(s.ID)
		}
		fmt.Fprintf(&b, "Session: %s\n", text(id))
		if !known {
			fmt.Fprintln(&b, "Tainted: unknown (no persisted session state).")
		} else if s.Tainted {
			fmt.Fprintln(&b, "Tainted: yes")
			seen := map[string]bool{}
			for _, e := range s.TaintEvents {
				label := string(e.Source) + " (" + e.Tool + ")"
				if !seen[label] {
					fmt.Fprintf(&b, "Source: %s\n", text(label))
					seen[label] = true
				}
			}
		} else {
			fmt.Fprintln(&b, "Tainted: no")
		}
		fmt.Fprintf(&b, "Asks in retained history: %d\n", h.Asks)
	}
	if len(files) == 0 {
		fmt.Fprintln(&b, "Policy files: none; built-in defaults are in effect.")
	} else {
		fmt.Fprintln(&b, "Policy files in effect:")
		for _, file := range files {
			fmt.Fprintln(&b, "  "+text(file))
		}
	}
	_, e := io.WriteString(w, b.String())
	return e
}
