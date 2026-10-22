package main

import (
	"flag"
	"fmt"
	"io"

	corpus "github.com/ratuhin1122/taintwatch/internal/eval"
)

func runEval(args []string, out, errOut io.Writer) int {
	help := func() {
		fmt.Fprintln(out, "Usage: taintwatch eval validate [CORPUS_DIR]\nDefault: eval/corpus. Validates sequences and metadata only; does not replay tools.")
	}
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		help()
		return exitOK
	}
	if args[0] != "validate" {
		fmt.Fprintln(errOut, "eval supports only validate")
		return exitUsage
	}
	f := flag.NewFlagSet("eval validate", flag.ContinueOnError)
	f.SetOutput(errOut)
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		help()
		return exitOK
	}
	if err := f.Parse(args[1:]); err != nil || f.NArg() > 1 {
		fmt.Fprintln(errOut, "invalid eval validate arguments")
		return exitUsage
	}
	root := "eval/corpus"
	if f.NArg() == 1 {
		root = f.Arg(0)
	}
	s, err := corpus.Validate(root)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return exitFailure
	}
	fmt.Fprintf(out, "Valid corpus: %d scenarios (%d attacks, %d benign), %d steps, %d action expectations, %d known misses.\nValidation only; no hooks or tools were executed, and no effectiveness metrics were measured.\n", s.Files, s.Attacks, s.Benign, s.Steps, s.Expectations, s.KnownMisses)
	return exitOK
}
