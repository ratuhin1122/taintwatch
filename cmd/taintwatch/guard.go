package main

import (
	"context"
	"github.com/ratuhin1122/taintwatch/internal/state"
	"io"
	"strings"
	"sync/atomic"
	"time"
)

// Context bounds both evaluation and output. Arbitrary Reader/Writer and kernel
// filesystem calls cannot be forcibly cancelled in Go; main's 2s process
// watchdog is the final bound and terminates any stuck worker goroutines.
const postTimeout = 1800 * time.Millisecond
const hookHardTimeout = 2 * time.Second

var watchdogClosed atomic.Bool

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(b []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	n, e := r.reader.Read(b)
	if ce := r.ctx.Err(); ce != nil {
		return 0, ce
	}
	return n, e
}

func initialClosed(args []string) bool {
	return explicitMode(args) != "open"
}
func explicitMode(args []string) string {
	mode := ""
	for i, arg := range args {
		if strings.HasPrefix(arg, "--fail-mode=") {
			mode = strings.TrimPrefix(arg, "--fail-mode=")
		}
		if strings.HasPrefix(arg, "-fail-mode=") {
			mode = strings.TrimPrefix(arg, "-fail-mode=")
		}
		if (arg == "--fail-mode" || arg == "-fail-mode") && i+1 < len(args) {
			mode = args[i+1]
		}
	}
	if mode == "open" || mode == "closed" {
		return mode
	}
	return ""
}

func guardedHook(args []string, in io.Reader, out, errOut io.Writer, timeout time.Duration, post bool, work func(context.Context, io.Reader, func(string)) postOutcome) int {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	workerCtx, stop := context.WithTimeout(ctx, timeout*3/4)
	defer stop()
	var closed atomic.Bool
	closed.Store(initialClosed(args))
	watchdogClosed.Store(closed.Load())
	observe := func(mode string) { closed.Store(mode == "closed"); watchdogClosed.Store(mode == "closed") }
	mode := func() string {
		if closed.Load() {
			return "closed"
		}
		return "open"
	}
	failure := func(stage string) postOutcome {
		if post {
			if store, err := state.New(state.Options{}); err == nil {
				_, _ = store.MarkDegraded("", "post observation lost: "+stage)
			}
			return postFailure(mode(), stage)
		}
		if stage == "deadline" {
			return preFailure("closed", stage)
		}
		return preFailure(mode(), stage)
	}
	done := make(chan postOutcome, 1)
	go func() {
		defer func() {
			if recover() != nil {
				done <- failure("internal panic")
			}
		}()
		done <- work(workerCtx, contextReader{workerCtx, in}, observe)
	}()
	var result postOutcome
	select {
	case result = <-done:
	case <-workerCtx.Done():
		result = failure("deadline")
	}
	result.closed = closed.Load()
	written := make(chan int, 1)
	go func() {
		defer func() {
			if recover() != nil {
				if !post && closed.Load() {
					written <- 2
				} else {
					written <- 0
				}
			}
		}()
		if result.help != "" {
			_, _ = io.WriteString(out, result.help)
			written <- 0
			return
		}
		if post {
			written <- finishPost(result, out, errOut)
		} else {
			written <- finishPre(result, out, errOut)
		}
	}()
	select {
	case code := <-written:
		return code
	case <-ctx.Done():
		if !post && closed.Load() {
			return 2
		}
		return 0
	}
}
