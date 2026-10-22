package hooks

import (
	"context"
	"io"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/detect/hidden"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"github.com/ratuhin1122/taintwatch/internal/taint"
)

// Post records a completed tool's provenance and informational content findings.
func Post(ctx context.Context, stdin io.Reader, override, profile string, observe func(string), classifier *taint.Classifier, rt Runtime) Outcome {
	rt = rt.defaults()
	if override != "" && observe != nil {
		observe(override)
	}
	boot, _ := rt.Bootstrap()
	mode := boot.Config.FailMode
	if override != "" {
		mode = override
	}
	if observe != nil {
		observe(mode)
	}
	input, err := hookio.DecodePostToolUse(stdin)
	if err != nil {
		return postFailure(mode, "input decoding")
	}
	loaded, policyErr := rt.LoadPolicy(input.CWD, override, profile)
	mode = loaded.Config.FailMode
	if observe != nil {
		observe(mode)
	}
	warning := policyWarning(loaded, policyErr)
	if ctx.Err() != nil {
		return postFailure(mode, "deadline")
	}
	store, err := rt.Store(loaded.Config)
	if err != nil {
		return postFailure(mode, "state initialization")
	}
	record := audit.Record{Session: input.SessionID, Hook: "PostToolUse", Tool: input.ToolName, Decision: "allow", FailMode: mode}
	if warning != "" {
		record.PolicyWarnings = []string{warning}
	}
	failure := func(stage string) Outcome {
		record.Rule = "post.error"
		record.Reason = "post hook error at " + stage + "; state persistence not confirmed"
		record.StateKnown = false
		if err := audit.Write(store, record); err != nil {
			return postFailure(mode, stage+" and audit persistence")
		}
		return postFailure(mode, stage)
	}
	if classifier == nil {
		classifier, err = taint.New(taint.FromPolicy(loaded.Config))
		if err != nil {
			return failure("source policy")
		}
	}
	args, err := input.SourceArguments()
	if err != nil {
		return failure("tool arguments")
	}
	in := taint.Input{Tool: input.ToolName, CWD: input.CWD, Command: args.Command, FilePath: args.FilePath}
	if input.MCPServer != nil {
		in.MCPServerName = input.MCPServer.Name
	}
	m, err := classifier.Classify(in)
	if err != nil {
		return failure("source classification")
	}
	if m.Tainted {
		text, truncated := input.ResponseText(hidden.MaxBytes)
		report := hidden.Scan(text)
		report.Truncated = report.Truncated || truncated
		record.Hidden = &report
	}
	parseFailed := input.ToolName == "Bash" && shellparse.Parse(args.Command).Unparseable
	if ctx.Err() != nil {
		return postFailure(mode, "deadline")
	}
	var session state.Session
	if m.Tainted {
		session, err = store.MarkTainted(input.SessionID, state.TaintEvent{Tool: input.ToolName, Source: m.Source, Reason: m.Reason})
	} else {
		session, err = store.Touch(input.SessionID)
	}
	if err != nil {
		outcome := failure("state update")
		if m.Tainted {
			outcome.Result = hookio.AdditionalContext(m.Context())
		}
		return outcome
	}
	if ctx.Err() != nil {
		return postFailure(mode, "deadline")
	}
	record.Rule = m.Rule
	record.Reason = m.Reason
	if parseFailed {
		record.Rule = "post.error"
		record.Reason = "post hook error at shell parsing; provenance classified conservatively"
	}
	record.Tainted = session.Tainted
	record.StateKnown = true
	seen := map[string]bool{}
	for _, event := range session.TaintEvents {
		source := string(event.Source)
		if !seen[source] {
			seen[source] = true
			record.TaintSources = append(record.TaintSources, source)
		}
	}
	if err := audit.Write(store, record); err != nil {
		o := postFailure(mode, "audit persistence")
		if m.Tainted {
			o.Result = hookio.AdditionalContext(m.Context())
		}
		return o
	}
	if m.Tainted {
		return Outcome{Result: hookio.AdditionalContext(m.Context()), Failure: warning}
	}
	if parseFailed {
		return postFailure(mode, "shell parsing")
	}
	if policyErr != nil && mode == "closed" {
		return postFailure(mode, "policy loading")
	}
	return Outcome{Failure: warning}
}
