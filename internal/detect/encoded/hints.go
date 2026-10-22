package encoded

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/ratuhin1122/taintwatch/internal/detect/decoderun"
	"github.com/ratuhin1122/taintwatch/internal/shellparse"
	"github.com/ratuhin1122/taintwatch/internal/valuematch"
)

var instructions = []string{"ignore previous instructions", "ignore all previous", "ignore the user", "disregard previous", "system prompt", "developer message", "do not ask", "don't ask", "without confirmation", "follow these instructions", "execute this command", "run this command", "send the secret", "upload the secret"}
var secretPath = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(?:\.env[a-z0-9_.-]*|[^\s/]+\.(?:pem|key|tfstate)|\.ssh(?:/|\b)|\.aws(?:/|\b)|\.config/gcloud(?:/|\b)|\.kube/config|\.npmrc|\.pypirc|\.netrc|\.git-credentials|id_rsa[a-z0-9_.-]*|\.docker/config\.json|\.(?:bash|zsh)_history)(?:$|[^a-z0-9_])`)
var mapVersion = regexp.MustCompile(`"version"\s*:\s*3\s*[,}]`)
var mapSources = regexp.MustCompile(`"sources"\s*:\s*\[`)
var mapMappings = regexp.MustCompile(`"mappings"\s*:\s*"`)

func sourceMap(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") && mapVersion.MatchString(s) && mapSources.MatchString(s) && mapMappings.MatchString(s) && json.Valid([]byte(s))
}

// Hints are deliberately non-exhaustive, fixed descriptions. No decoded text,
// secret path, URL or token is retained. Each type counts blobs, not phrases.
func hints(text string) []string {
	out := []string{}
	lower := strings.ToLower(text)
	for _, p := range instructions {
		if strings.Contains(lower, p) {
			out = append(out, "instruction-like")
			break
		}
	}
	if secretPath.MatchString(text) {
		out = append(out, "secret-path")
	}
	for _, v := range valuematch.Extract(text) {
		if v.Kind == "url" {
			out = append(out, "url")
			break
		}
	}
	if decoderun.Analyze(shellparse.Parse(text)).Matched() {
		out = append(out, "decode-and-run")
	}
	return out
}
