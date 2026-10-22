package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestInstallationHelp(t *testing.T) {
	for _, name := range []string{"install", "uninstall", "doctor"} {
		var out, errOut bytes.Buffer
		if code := run([]string{name, "--help"}, strings.NewReader(""), &out, &errOut); code != 0 || !strings.Contains(out.String(), "Usage:") || errOut.Len() != 0 {
			t.Fatalf("%s %d %s %s", name, code, out.String(), errOut.String())
		}
		out.Reset()
		if code := run([]string{name, "unexpected"}, strings.NewReader(""), &out, &errOut); code != 2 {
			t.Fatal(name, code)
		}
	}
}
