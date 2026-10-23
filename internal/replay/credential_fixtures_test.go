package replay

import "strings"

// fakeCredential keeps complete scanner patterns out of source while preserving runtime controls.
func fakeCredential(prefix, suffix string) string { return strings.Join([]string{prefix, suffix}, "") }
