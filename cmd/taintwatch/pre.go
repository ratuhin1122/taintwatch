package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/ratuhin1122/taintwatch/internal/hookio"
	"github.com/ratuhin1122/taintwatch/internal/hooks"
)

func preFailure(mode, stage string) postOutcome {
	o := postOutcome{failure: stage}
	if mode == "closed" {
		o.result = hookio.Ask("Taintwatch could not complete the safety check (" + stage + "); confirm this action before proceeding.")
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
	o := hooks.Pre(ctx, reader, override, observe, hooks.Runtime{})
	return postOutcome{result: o.Result, failure: o.Failure}
}
