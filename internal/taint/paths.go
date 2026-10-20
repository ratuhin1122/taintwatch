package taint

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/state"
)

func (c *Classifier) classifyRead(in Input) Match {
	readMatch := func(rule, reason string) Match { return match(state.SourceRead, rule, reason) }
	if c.policy.Profile == "paranoid" {
		return readMatch("taint.read-paranoid", "paranoid profile treats every Read as untrusted")
	}
	if in.FilePath == "" || !filepath.IsAbs(in.CWD) {
		return readMatch("taint.read-unresolved", "Read path or project root could not be established")
	}
	full := in.FilePath
	if !filepath.IsAbs(full) {
		full = strings.TrimRight(in.CWD, string(filepath.Separator)) + string(filepath.Separator) + full
	}
	// Preserve symlink/.. ordering for EvalSymlinks. filepath.Join or Abs would
	// clean away .. too early and can turn an escaping path into an apparent local one.
	root, rootErr := filepath.EvalSymlinks(in.CWD)
	resolved, resolveErr := filepath.EvalSymlinks(full)
	if rootErr != nil || resolveErr != nil {
		return readMatch("taint.read-unresolved", "Read path could not be resolved safely")
	}
	lexical := filepath.Clean(full)
	if outside(filepath.Clean(in.CWD), lexical) || outside(root, resolved) {
		return readMatch("taint.read-outside", "file is outside the project root")
	}
	for _, glob := range c.policy.UntrustedGlobs {
		if globMatch(glob, slash(lexical)) || globMatch(glob, slash(resolved)) {
			return readMatch("taint.read-glob", "file matches an untrusted source glob")
		}
	}
	for _, dir := range append(append([]string{}, c.policy.TempPaths...), c.policy.DownloadedPaths...) {
		if dir == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			dir = in.CWD + string(filepath.Separator) + dir
		}
		if !outside(filepath.Clean(dir), lexical) {
			return readMatch("taint.read-download", "file is in a temporary or downloaded-content directory")
		}
		if realDir, err := filepath.EvalSymlinks(dir); err == nil && !outside(realDir, resolved) {
			return readMatch("taint.read-download", "file is in a temporary or downloaded-content directory")
		}
	}
	return Match{Rule: "source.project-read", Reason: "file is an ordinary project source"}
}

func outside(root, file string) bool {
	rel, err := filepath.Rel(root, file)
	return err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func slash(s string) string { return strings.ReplaceAll(filepath.ToSlash(s), `\`, "/") }

// globMatch implements segment globbing with ** for zero or more complete path
// segments. Its iterative DP avoids recursion on adversarially deep paths.
func globMatch(pattern, value string) bool {
	segments := strings.Split(value, "/")
	dp := make([]bool, len(segments)+1)
	dp[0] = true
	for _, part := range strings.Split(pattern, "/") {
		next := make([]bool, len(dp))
		if part == "**" {
			next[0] = dp[0]
			for j := 1; j < len(next); j++ {
				next[j] = dp[j] || next[j-1]
			}
		} else {
			for j := 1; j < len(next); j++ {
				ok, _ := path.Match(part, segments[j-1])
				next[j] = dp[j-1] && ok
			}
		}
		dp = next
	}
	return dp[len(segments)]
}
