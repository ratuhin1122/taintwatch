//go:build !linux && !darwin

package main

import "io"

func terminalInput(io.Reader) bool { return false }
