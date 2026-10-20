package hookio

import "encoding/json"

// CommonInput contains the documented fields shared by hook events. Strings are
// untrusted data: decoding does not sanitize them for paths or shell execution.
// Optional fields have zero values when omitted; unknown fields are ignored.
type CommonInput struct {
	SessionID      string  `json:"session_id"`
	CWD            string  `json:"cwd"`
	TranscriptPath string  `json:"transcript_path"`
	HookEventName  string  `json:"hook_event_name"`
	PermissionMode string  `json:"permission_mode,omitempty"`
	PromptID       string  `json:"prompt_id,omitempty"`
	ScratchpadDir  string  `json:"scratchpad_dir,omitempty"`
	AgentID        string  `json:"agent_id,omitempty"`
	AgentType      string  `json:"agent_type,omitempty"`
	Effort         *Effort `json:"effort,omitempty"`
}

// Effort describes the optional documented model effort object. Level remains a
// string so future levels do not break transport decoding.
type Effort struct {
	Level string `json:"level"`
}

// MCPServer is the optional documented MCP provenance object (Claude Code
// 2.1.274+). An absent object or an unknown source must not imply trust.
type MCPServer struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// ToolEventInput is the documented envelope common to PreToolUse and PostToolUse.
// ToolInput stays opaque until a tool-specific adapter has a verified schema.
// ToolUseID is optional for compatibility with versions predating that field.
type ToolEventInput struct {
	CommonInput
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	MCPServer *MCPServer      `json:"mcp_server,omitempty"`
}

// PreToolUseInput is the documented input before a tool executes.
type PreToolUseInput struct {
	ToolEventInput
}

// PostToolUseInput is the documented input after a tool completes successfully.
// ToolResponse accepts any JSON shape, including null. Real Read, WebFetch, Bash,
// and MCP result variants remain unverified; no concrete result shape is assumed.
type PostToolUseInput struct {
	ToolEventInput
	ToolResponse json.RawMessage `json:"tool_response"`
	DurationMS   *float64        `json:"duration_ms,omitempty"`
}

// UserPromptSubmitInput contains submitted prompt text. Pasted content is left
// intact; the transport layer does not interpret it or make trust decisions.
type UserPromptSubmitInput struct {
	CommonInput
	Prompt string `json:"prompt"`
}

// SessionStartInput describes a session lifecycle start. Source is not restricted
// to an enum so future sources remain decodable. Model and SessionTitle may be
// absent, including when a session is cleared or recovered.
type SessionStartInput struct {
	CommonInput
	Source       string `json:"source"`
	Model        string `json:"model,omitempty"`
	SessionTitle string `json:"session_title,omitempty"`
}
