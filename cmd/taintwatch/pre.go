package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/policy"
	"github.com/ratuhin1122/taintwatch/internal/rules"
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func preFailure(mode, stage string) postOutcome {
	o := postOutcome{failure: stage}
	if mode == "closed" {
		o.result = hookio.Ask("Taintwatch could not complete the safety check (" + stage + "); confirm this action before proceeding.")
	}
	return o
}
func preFailureKnown(mode, stage string, d rules.Decision) postOutcome {
	o := preFailure(mode, stage)
	if d.Action == rules.Ask {
		o.result = hookio.Ask(d.Reason)
	} else if d.Action == rules.Deny {
		o.result = hookio.Deny(d.Reason)
	}
	return o
}
func finishPre(o postOutcome, out, errOut io.Writer) int {
	if _, err := o.result.Write(out); err != nil {
		fmt.Fprintln(errOut, "taintwatch pre: hook output unavailable")
		if o.closed {
			return 2
		}
	}
	if o.failure != "" {
		fmt.Fprintln(errOut, "taintwatch pre: internal error at "+o.failure)
	}
	return exitOK
}
func runPre(args []string, in io.Reader, out, errOut io.Writer) int {
	return runPreWithin(args, in, out, errOut, postTimeout)
}
func runPreWithin(args []string, in io.Reader, out, errOut io.Writer, timeout time.Duration) int {
	return guardedHook(args, in, out, errOut, timeout, false, func(ctx context.Context, reader io.Reader, observe func(string)) postOutcome {
		return preWork(ctx, args, reader, observe)
	})
}
func preWork(ctx context.Context, args []string, in io.Reader, observe func(string)) postOutcome {
	f := flag.NewFlagSet("hook pre", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	mode := f.String("fail-mode", "", "internal error behavior; default from policy")
	if err := f.Parse(args); err == flag.ErrHelp {
		return postOutcome{help: "Usage: taintwatch hook pre [--fail-mode open|closed]\n"}
	} else if err != nil || f.NArg() != 0 {
		fallback := *mode
		if fallback == "" {
			fallback = explicitMode(args)
		}
		fallback = userErrorMode(fallback)
		observe(fallback)
		return preFailure(fallback, "configuration")
	}
	if *mode != "" && *mode != "open" && *mode != "closed" {
		fallback := userErrorMode("")
		observe(fallback)
		return preFailure(fallback, "configuration")
	}
	return processPreContext(ctx, in, *mode, observe)
}
func processPre(reader io.Reader, mode string) postOutcome {
	return processPreObserved(reader, mode, nil)
}
func processPreObserved(reader io.Reader, override string, observe func(string)) postOutcome {
	return processPreContext(context.Background(), reader, override, observe)
}
func processPreContext(ctx context.Context, reader io.Reader, override string, observe func(string)) postOutcome {
	if override != "" && observe != nil {
		observe(override)
	}
	boot, _ := policy.Load(policy.Options{NoProject: true})
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
	loaded, policyErr := loadHookPolicy(in.CWD, override, "")
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
	p.StateHome, _ = state.DefaultHome()
	p.SelfPaths = append([]string{}, loaded.Files...)
	input := rules.Input{Policy: p, Tool: in.ToolName, CWD: in.CWD, Command: args.Command, FilePath: args.FilePath, URL: args.URL}
	if in.ToolName == "Bash" && argsErr == nil {
		input.Shell = shellparse.Parse(args.Command)
	}
	known := rules.Evaluate(input)
	store, err := policyStore(loaded.Config)
	if err != nil {
		return preFailureKnown(mode, "state initialization", known)
	}
	record := audit.Record{Session: in.SessionID, Hook: "PreToolUse", Tool: in.ToolName, FailMode: mode}
	if warning != "" {
		record.PolicyWarnings = []string{warning}
	}
	failure := func(stage string) postOutcome {
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
			o.failure += " and audit persistence"
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
	d := rules.Evaluate(input)
	if ctx.Err() != nil {
		return preFailure(mode, "deadline")
	}
	record.Decision = string(d.Action)
	record.Rule = d.RuleID
	record.Reason = d.Reason
	record.Evidence = d.Evidence
	if err := audit.Write(store, record); err != nil {
		o := preFailure(mode, "audit persistence")
		if d.Action == rules.Ask {
			o.result = hookio.Ask(d.Reason)
		} else if d.Action == rules.Deny {
			o.result = hookio.Deny(d.Reason)
		}
		return o
	}
	switch d.Action {
	case rules.Ask:
		return postOutcome{result: hookio.Ask(d.Reason), failure: warning}
	case rules.Deny:
		return postOutcome{result: hookio.Deny(d.Reason), failure: warning}
	}
	// Abstain rather than overriding Claude Code's own permission checks.
	return postOutcome{failure: warning}
}
