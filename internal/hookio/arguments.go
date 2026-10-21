package hookio

import (
	"encoding/json"
	"fmt"
)

// SourceArguments is the small, documented argument subset needed by provenance
// classification. It makes no assumptions about any tool_response shape.
type SourceArguments struct {
	Command  string
	FilePath string
	URL      string
}

// Post provenance needs only reader arguments, not mutation or URL arguments.
func (in PostToolUseInput) SourceArguments() (SourceArguments, error) {
	if in.ToolName != "Bash" && in.ToolName != "Read" {
		return SourceArguments{}, nil
	}
	return in.ToolEventInput.SourceArguments()
}

// SourceArguments extracts Bash command or Read file_path exclusively inside
// hookio. Both fields are documented in the official hooks input reference.
func (in ToolEventInput) SourceArguments() (SourceArguments, error) {
	var args SourceArguments
	switch in.ToolName {
	case "Bash":
		var v struct {
			Command *string `json:"command"`
		}
		if err := json.Unmarshal(in.ToolInput, &v); err != nil {
			return args, fmt.Errorf("decode Bash arguments: %w", err)
		}
		if v.Command == nil {
			return args, fmt.Errorf("%w: missing Bash command", ErrInvalidInput)
		}
		args.Command = *v.Command
	case "Read", "Write", "Edit":
		var v struct {
			FilePath *string `json:"file_path"`
		}
		if err := json.Unmarshal(in.ToolInput, &v); err != nil {
			return args, fmt.Errorf("decode Read arguments: %w", err)
		}
		if v.FilePath == nil || *v.FilePath == "" {
			return args, fmt.Errorf("%w: missing Read file_path", ErrInvalidInput)
		}
		args.FilePath = *v.FilePath
	case "WebFetch":
		var v struct {
			URL *string `json:"url"`
		}
		if err := json.Unmarshal(in.ToolInput, &v); err != nil {
			return args, err
		}
		if v.URL == nil || *v.URL == "" {
			return args, fmt.Errorf("%w: missing WebFetch url", ErrInvalidInput)
		}
		args.URL = *v.URL
	}
	return args, nil
}
