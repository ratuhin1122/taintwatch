package hookio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxInputBytes is the cap for the entire hook payload, including whitespace.
const MaxInputBytes = 8 << 20

var (
	// ErrInputTooLarge identifies a payload exceeding MaxInputBytes.
	ErrInputTooLarge = errors.New("hook input exceeds 8 MiB")
	// ErrInvalidInput identifies malformed JSON or an invalid input envelope.
	ErrInvalidInput = errors.New("invalid hook input")
	// ErrUnexpectedEvent identifies an event sent to the wrong decoder.
	ErrUnexpectedEvent = errors.New("unexpected hook event")
)

// DecodePreToolUse reads one size-limited PreToolUse object. Unknown fields and
// missing optional fields are tolerated. Tool input is retained as raw JSON.
func DecodePreToolUse(r io.Reader) (PreToolUseInput, error) {
	input, err := decode[PreToolUseInput](r)
	if err == nil {
		err = validateTool(input.ToolEventInput, "PreToolUse")
	}
	if err != nil {
		return PreToolUseInput{}, fmt.Errorf("decode PreToolUse: %w", err)
	}
	return input, nil
}

// DecodePostToolUse reads a size-limited successful-tool event. ToolResponse is
// required but remains opaque; its tool-specific shape is deliberately unchecked.
func DecodePostToolUse(r io.Reader) (PostToolUseInput, error) {
	input, err := decode[PostToolUseInput](r)
	if err == nil {
		err = validateTool(input.ToolEventInput, "PostToolUse")
	}
	if err == nil && len(input.ToolResponse) == 0 {
		err = fmt.Errorf("%w: missing tool_response", ErrInvalidInput)
	}
	if err != nil {
		return PostToolUseInput{}, fmt.Errorf("decode PostToolUse: %w", err)
	}
	return input, nil
}

// DecodeUserPromptSubmit reads a size-limited prompt event. An empty prompt is
// preserved; callers decide whether it has meaning for their policy.
func DecodeUserPromptSubmit(r io.Reader) (UserPromptSubmitInput, error) {
	input, err := decode[UserPromptSubmitInput](r)
	if err == nil {
		err = validateCommon(input.CommonInput, "UserPromptSubmit")
	}
	if err != nil {
		return UserPromptSubmitInput{}, fmt.Errorf("decode UserPromptSubmit: %w", err)
	}
	return input, nil
}

// DecodeSessionStart reads a size-limited session lifecycle event. Unknown source
// strings and missing optional metadata are accepted.
func DecodeSessionStart(r io.Reader) (SessionStartInput, error) {
	input, err := decode[SessionStartInput](r)
	if err == nil {
		err = validateCommon(input.CommonInput, "SessionStart")
	}
	if err != nil {
		return SessionStartInput{}, fmt.Errorf("decode SessionStart: %w", err)
	}
	return input, nil
}

func decode[T any](r io.Reader) (T, error) {
	var input T
	if r == nil {
		return input, fmt.Errorf("%w: nil input reader", ErrInvalidInput)
	}
	// Read at most one byte beyond the limit, including for endless readers.
	// The caller must separately bound elapsed time for a stalled stdin stream;
	// io.Reader has no general cancellation or deadline contract.
	b, err := io.ReadAll(io.LimitReader(r, MaxInputBytes+1))
	if err != nil {
		return input, fmt.Errorf("read hook input: %w", err)
	}
	if len(b) > MaxInputBytes {
		return input, ErrInputTooLarge
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return input, fmt.Errorf("%w: expected a JSON object", ErrInvalidInput)
	}
	// Unmarshal rejects trailing non-whitespace, including a second JSON object.
	// It does not disallow unknown fields, preserving forward compatibility.
	if err := json.Unmarshal(b, &input); err != nil {
		return input, fmt.Errorf("%w: decode JSON: %w", ErrInvalidInput, err)
	}
	return input, nil
}

// These checks are Taintwatch validation choices, not claims that every Claude
// Code release enforces field presence. See docs/ASSUMPTIONS.md for the boundary.
func validateCommon(input CommonInput, event string) error {
	if input.HookEventName != event {
		return fmt.Errorf("%w: expected %s", ErrUnexpectedEvent, event)
	}
	if input.SessionID == "" {
		return fmt.Errorf("%w: missing session_id", ErrInvalidInput)
	}
	return nil
}

func validateTool(input ToolEventInput, event string) error {
	if err := validateCommon(input.CommonInput, event); err != nil {
		return err
	}
	if input.ToolName == "" {
		return fmt.Errorf("%w: missing tool_name", ErrInvalidInput)
	}
	b := bytes.TrimSpace(input.ToolInput)
	if len(b) == 0 || b[0] != '{' {
		return fmt.Errorf("%w: tool_input must be an object", ErrInvalidInput)
	}
	return nil
}
