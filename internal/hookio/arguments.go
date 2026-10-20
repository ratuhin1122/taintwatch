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
}

// SourceArguments extracts Bash command or Read file_path exclusively inside
// hookio. Both fields are documented in the official hooks input reference.
func (in PostToolUseInput) SourceArguments() (SourceArguments, error) {
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
	case "Read":
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
	}
	return args, nil
}
