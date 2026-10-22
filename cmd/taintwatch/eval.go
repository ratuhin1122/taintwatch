package main

import (
	"context"
	"flag"
	"fmt"
	"io"

	corpus "github.com/ratuhin1122/taintwatch/internal/eval"
)

func runEval(args []string, out, errOut io.Writer) int {
	help := func() {
		fmt.Fprintln(out, "Usage: taintwatch eval validate [CORPUS_DIR]\n       taintwatch eval run [--json|--markdown] [CORPUS_DIR]\nDefault: eval/corpus. Replay evaluates hooks only; never executes tools.")
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		help()
		return exitOK
	}
	if args[0] != "validate" && args[0] != "run" {
		fmt.Fprintln(errOut, "eval supports validate or run")
		return exitUsage
	}
	f := flag.NewFlagSet("eval "+args[0], flag.ContinueOnError)
	var asJSON, asMarkdown *bool
	if args[0] == "run" {
		asJSON = f.Bool("json", false, "JSON metrics")
		asMarkdown = f.Bool("markdown", false, "Markdown tables")
	}
	f.SetOutput(errOut)
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		help()
		return exitOK
	}
	if err := f.Parse(args[1:]); err != nil || f.NArg() > 1 {
		fmt.Fprintln(errOut, "invalid eval "+args[0]+" arguments")
		return exitUsage
	}
	root := "eval/corpus"
	if f.NArg() == 1 {
		root = f.Arg(0)
	}
	if args[0] == "run" {
		if *asJSON && *asMarkdown {
			fmt.Fprintln(errOut, "choose either --json or --markdown")
			return exitUsage
		}
		r, err := corpus.Run(context.Background(), root)
		if err != nil {
			fmt.Fprintln(errOut, err)
			return exitFailure
		}
		format := "human"
		if *asJSON {
			format = "json"
		}
		if *asMarkdown {
			format = "markdown"
		}
		if err = corpus.Render(out, r, format); err != nil {
			fmt.Fprintln(errOut, "could not write eval report")
			return exitFailure
		}
		if r.GateFailures > 0 {
			return exitFailure
		}
		return exitOK
	}
	s, err := corpus.Validate(root)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitFailure
	}
	fmt.Fprintf(out, "Valid corpus: %d scenarios (%d attacks, %d benign), %d steps, %d action expectations, %d known misses.\nValidation only; no hooks or tools were executed, and no effectiveness metrics were measured.\n", s.Files, s.Attacks, s.Benign, s.Steps, s.Expectations, s.KnownMisses)
	return exitOK
}
