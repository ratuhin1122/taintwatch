package install

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestPackaging(t *testing.T) {
	var plugin struct {
		Name, Version string
		Keywords      []string
	}
	b, e := os.ReadFile("../../.claude-plugin/plugin.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &plugin); e != nil {
		t.Fatal(e)
	}
	if plugin.Name != "taintwatch" || plugin.Version == "" {
		t.Fatal(plugin)
	}
	for _, file := range []string{"../../bin/taintwatch-launcher", "../../scripts/release-assets.sh"} {
		b, e := os.ReadFile(file)
		if e != nil || !strings.Contains(string(b), "version="+plugin.Version+"\n") {
			t.Fatal("version mismatch", file, e)
		}
	}
	for _, tag := range []string{"claude-code", "prompt-injection", "taint-tracking", "ai-agent-security", "guardrails", "mcp-security", "secret-protection", "data-exfiltration", "audit-log"} {
		found := false
		for _, v := range plugin.Keywords {
			found = found || v == tag
		}
		if !found {
			t.Fatal("missing keyword", tag)
		}
	}
	if !PluginWired("../..") {
		t.Fatal("plugin hooks not wired")
	}
}
