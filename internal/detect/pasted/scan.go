package pasted

import (
	"regexp"
	"strings"
)

const MaxBytes = 1 << 20

// Report contains counters only. No prompt text or log lines are retained.
type Report struct {
	BytesScanned int  `json:"bytes_scanned"`
	Truncated    bool `json:"truncated"`
	FencedBlocks int  `json:"fenced_blocks"`
	LogLines     int  `json:"log_lines"`
	LongLog      bool `json:"long_log"`
}

var logPrefix = regexp.MustCompile(`(?i)^(?:(?:\[[^\]\r\n]{1,40}\]\s*)?(?:TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL)\b|\d{4}-\d{2}-\d{2}[ T]|\d{2}:\d{2}:\d{2}\b|at\s+\S+\(|[A-Za-z0-9_./-]+\.go:\d+:)`)

// Scan walks at most the first MiB once, using a linear-time prefix expression
// on each disjoint line. A long-log hint requires 4 KiB, 40 log-like lines, and
// at least half of nonblank lines looking like logs. Fences are Markdown-like
// backticks or tildes (3+), allowing up to three spaces of indentation.
func Scan(s string) Report {
	r := Report{Truncated: len(s) > MaxBytes}
	if r.Truncated {
		s = s[:MaxBytes]
	}
	r.BytesScanned = len(s)
	var fence byte
	width, lines := 0, 0
	for len(s) > 0 {
		n := strings.IndexByte(s, '\n')
		if n < 0 {
			n = len(s)
		}
		line := strings.TrimSuffix(s[:n], "\r")
		if n == len(s) {
			s = ""
		} else {
			s = s[n+1:]
		}
		trim := strings.TrimSpace(line)
		if trim != "" {
			lines++
			if logPrefix.MatchString(trim) {
				r.LogLines++
			}
		}
		ind := 0
		for ind < len(line) && line[ind] == ' ' {
			ind++
		}
		if ind > 3 || ind == len(line) {
			continue
		}
		line = line[ind:]
		c := line[0]
		if c != '`' && c != '~' {
			continue
		}
		count := 0
		for count < len(line) && line[count] == c {
			count++
		}
		if count < 3 {
			continue
		}
		if fence == 0 {
			if c == '`' && strings.ContainsRune(line[count:], '`') {
				continue
			}
			r.FencedBlocks++
			fence = c
			width = count
		} else if c == fence && count >= width && strings.TrimSpace(line[count:]) == "" {
			fence = 0
			width = 0
		}
	}
	r.LongLog = r.BytesScanned >= 4096 && r.LogLines >= 40 && r.LogLines*2 >= lines
	return r
}
