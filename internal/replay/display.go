package replay

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/ratuhin1122/taintwatch/internal/audit"
)

func display(s string) string {
	var b strings.Builder
	for _, r := range audit.Redact(s) {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			fmt.Fprintf(&b, "<U+%04X>", r)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}
