package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/ratuhin1122/taintwatch/internal/replay"
)

func runReplay(args []string, out, errOut io.Writer) int {
	f := flag.NewFlagSet("replay", flag.ContinueOnError)
	f.SetOutput(errOut)
	log := f.String("log", "", "redacted JSONL audit log")
	policy := f.String("policy", "", "candidate YAML, applied over built-in defaults only")
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Usage: taintwatch replay --log audit.jsonl --policy new.yaml\nRead-only action/enable replay from complete redacted match snapshots; legacy records are marked unreplayable.")
		return exitOK
	}
	if err := f.Parse(args); err != nil || f.NArg() != 0 || *log == "" || *policy == "" {
		fmt.Fprintln(errOut, "replay requires --log FILE and --policy FILE")
		return exitUsage
	}
	r, err := replay.Run(*log, *policy)
	if err != nil {
		fmt.Fprintln(errOut, "replay:", err)
		return exitFailure
	}
	if err = replay.Render(out, r); err != nil {
		fmt.Fprintln(errOut, "could not write replay diff")
		return exitFailure
	}
	return exitOK
}
