package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ratuhin1122/taintwatch/internal/audit"
	"github.com/ratuhin1122/taintwatch/internal/explain"
	"github.com/ratuhin1122/taintwatch/internal/state"
)

func runInspect(name string, args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(errOut)
	sessionID := flags.String("session", "", "session ID; default most recent")
	last := 10
	asJSON := false
	if name == "explain" {
		flags.IntVar(&last, "last", 10, "recent decisions (1..1000)")
		flags.BoolVar(&asJSON, "json", false, "structured output")
	}
	flags.Usage = func() {
		fmt.Fprintf(flags.Output(), "Usage: taintwatch %s [--session ID]", name)
		if name == "explain" {
			fmt.Fprint(flags.Output(), " [--last N] [--json]")
		}
		fmt.Fprintln(flags.Output())
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		flags.SetOutput(out)
		flags.Usage()
		return exitOK
	}
	if e := flags.Parse(args); e != nil {
		return exitUsage
	}
	if flags.NArg() != 0 || last < 1 || last > 1000 {
		fmt.Fprintln(errOut, "invalid arguments; --last must be 1..1000")
		return exitUsage
	}
	store, e := state.New(state.Options{})
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": state is unavailable")
		return exitFailure
	}
	h, e := audit.Query(store, *sessionID, last)
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": could not read audit history")
		return exitFailure
	}
	if name == "explain" {
		e = explain.Render(out, h, asJSON)
	} else {
		var current state.Session
		known := false
		if *sessionID != "" {
			current, e = store.Load(*sessionID)
			known = e == nil
		} else if h.Session != "" {
			current, known, e = store.LoadKey(h.Session)
		} else {
			current, known, e = store.Latest()
			if known {
				h, e = audit.Query(store, current.ID, last)
			}
		}
		if e != nil {
			fmt.Fprintln(errOut, "taintwatch status: could not read session state")
			return exitFailure
		}
		e = explain.Status(out, current, known, h)
	}
	if e != nil {
		fmt.Fprintln(errOut, "taintwatch "+name+": output unavailable")
		return exitFailure
	}
	return exitOK
}
