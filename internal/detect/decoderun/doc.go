// Package decoderun detects structural flows from decoders (or downloaders)
// into executable shell/interpreter inputs. It never executes code, decodes the
// payload itself, reads files, or treats unrelated commands as a shared flow.
// It is a best-effort command-behavior detector, not a content classifier.
package decoderun
