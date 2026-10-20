package hookio

import (
	"encoding/json"
	"fmt"
	"io"
)

// Result is a hook response. Construct it with Allow, Ask, Deny, or
// AdditionalContext; its zero value abstains with {} and exit code 0.
// Callers must not translate a JSON deny into exit 2: structured decisions use 0.
type Result struct {
	kind resultKind
	text string
}

type resultKind uint8

const (
	abstain resultKind = iota
	allow
	ask
	deny
	context
)

// Allow explicitly approves a PreToolUse call. Use a zero Result to leave normal
// Claude Code permission processing in place instead of explicitly approving it.
func Allow() Result { return Result{kind: allow} }

// Ask requests user confirmation for a PreToolUse call, displaying reason.
func Ask(reason string) Result { return Result{kind: ask, text: reason} }

// Deny rejects a PreToolUse call with reason. Policy callers should use it only
// for an explicit deny policy; content telemetry alone must never select it.
func Deny(reason string) Result { return Result{kind: deny, text: reason} }

// AdditionalContext adds text alongside a completed PostToolUse result. It cannot
// prevent or undo execution. Verified in docs/ASSUMPTIONS.md, PostToolUse stdout.
func AdditionalContext(text string) Result { return Result{kind: context, text: text} }

type preToolUseOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type postToolUseOutput struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

// ExitCode is 0 for all structured results, including deny. This keeps decision
// semantics in the verified JSON rather than Claude Code's blocking-error channel.
func (r Result) ExitCode() int { return 0 }

// Write writes exactly one JSON object followed by a newline, with no diagnostics.
// On success it returns ExitCode(). On output failure it returns 1 and a wrapped
// error; the hook entry point must apply its configured failure policy. This
// package neither exits the process nor selects open/closed policy for the caller.
func (r Result) Write(w io.Writer) (int, error) {
	if w == nil {
		return 1, fmt.Errorf("write hook result: nil output writer")
	}
	var output any = struct{}{}
	switch r.kind {
	case abstain:
	case allow, ask, deny:
		decision := map[resultKind]string{allow: "allow", ask: "ask", deny: "deny"}[r.kind]
		output = struct {
			HookSpecificOutput preToolUseOutput `json:"hookSpecificOutput"`
		}{
			preToolUseOutput{"PreToolUse", decision, r.text},
		}
	case context:
		output = struct {
			HookSpecificOutput postToolUseOutput `json:"hookSpecificOutput"`
		}{
			postToolUseOutput{"PostToolUse", r.text},
		}
	default:
		return 1, fmt.Errorf("encode hook result: invalid result kind %d", r.kind)
	}
	b, err := json.Marshal(output)
	if err != nil {
		return 1, fmt.Errorf("encode hook result: %w", err)
	}
	b = append(b, '\n')
	n, err := w.Write(b)
	if err != nil {
		return 1, fmt.Errorf("write hook result: %w", err)
	}
	if n != len(b) {
		return 1, fmt.Errorf("write hook result: %w", io.ErrShortWrite)
	}
	return r.ExitCode(), nil
}
