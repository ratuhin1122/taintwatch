package hooks

import (
	"context"
	"io"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/rules"
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
)

// Pre processes a requested action using current session state and the rule table.
func Pre(ctx context.Context, reader io.Reader, override string, observe func(string), rt Runtime) Outcome {
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
	in, err := hookio.DecodePreToolUse(reader)
	if err != nil {
		return preFailure(mode, "input decoding")
	}
	loaded, policyErr := rt.LoadPolicy(in.CWD, override, "")
	mode = loaded.Config.FailMode
	if observe != nil {
		observe(mode)
	}
	warning := policyWarning(loaded, policyErr)
	if ctx.Err() != nil {
		return preFailure(mode, "deadline")
	}
	// Always rules do not depend on reading session state. Preserve self-protection
	// and decode/run decisions even when state initialization or loading fails open.
	args, argsErr := in.SourceArguments()
	p := rules.FromPolicy(loaded.Config)
	p.StateHome, _ = rt.StateHome()
	p.SelfPaths = append([]string{}, loaded.Files...)
	input := rules.Input{Policy: p, Tool: in.ToolName, CWD: in.CWD, Command: args.Command, FilePath: args.FilePath, URL: args.URL}
	if in.ToolName == "Bash" && argsErr == nil {
		input.Shell = shellparse.Parse(args.Command)
	}
	known := rules.Evaluate(input)
	store, err := rt.Store(loaded.Config)
	if err != nil {
		return preFailureKnown(mode, "state initialization", known)
	}
	record := audit.Record{Session: in.SessionID, Hook: "PreToolUse", Tool: in.ToolName, FailMode: mode}
	if warning != "" {
		record.PolicyWarnings = []string{warning}
	}
	failure := func(stage string) Outcome {
		record.Rule = "pre.error"
		record.Reason = "pre hook error at " + stage
		record.Decision = "allow"
		if mode == "closed" {
			record.Decision = "ask"
		}
		o := preFailureKnown(mode, stage, known)
		if known.Action == rules.Ask || known.Action == rules.Deny {
			record.Rule = known.RuleID
			record.Reason = known.Reason
			record.Decision = string(known.Action)
			record.Evidence = known.Evidence
		}
		if audit.Write(store, record) != nil {
			o.Failure += " and audit persistence"
		}
		return o
	}
	if policyErr != nil && mode == "closed" {
		return failure("policy loading")
	}
	if argsErr != nil {
		return failure("tool arguments")
	}
	session, err := store.Load(in.SessionID)
	if err != nil {
		return failure("state loading")
	}
	record.StateKnown = true
	record.Tainted = session.Tainted
	for _, e := range session.TaintEvents {
		record.TaintSources = append(record.TaintSources, string(e.Source))
	}
	p.StateHome = store.Home()
	p.SelfPaths = append(append([]string{}, loaded.Files...), store.AuditFile())
	input.Policy = p
	input.Session = session
	if in.ToolName == "Bash" {
		if input.Shell.Unparseable && !session.Tainted {
			return failure("shell parsing")
		}
	}
	if ctx.Err() != nil {
		return preFailure(mode, "deadline")
	}
	d, snapshot := rules.EvaluateTraced(input)
	snapshot.Fingerprint = rules.MatchFingerprint(loaded.Config)
	if ctx.Err() != nil {
		return preFailure(mode, "deadline")
	}
	record.Decision = string(d.Action)
	record.Rule = d.RuleID
	record.Reason = d.Reason
	record.Evidence = d.Evidence
	// Successful decisions retain only complete redacted match facts. Error and
	// incomplete-policy records cannot be promoted into replayable observations.
	if policyErr == nil {
		record.Replay = &snapshot
	}
	if err := audit.Write(store, record); err != nil {
		o := preFailure(mode, "audit persistence")
		if d.Action == rules.Ask {
			o.Result = hookio.Ask(d.Reason)
		} else if d.Action == rules.Deny {
			o.Result = hookio.Deny(d.Reason)
		}
		return o
	}
	switch d.Action {
	case rules.Ask:
		return Outcome{Result: hookio.Ask(d.Reason), Failure: warning}
	case rules.Deny:
		return Outcome{Result: hookio.Deny(d.Reason), Failure: warning}
	}
	// Abstain rather than overriding Claude Code's own permission checks.
	return Outcome{Failure: warning}
}
