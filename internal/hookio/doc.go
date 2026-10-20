// Package hookio isolates Claude Code hook formats and transport handling.
// Structured output is based on the verified documentation in docs/ASSUMPTIONS.md.
// Input structs use the documented envelope; real-session verification is pending.
// Tool-specific input and response schemas remain opaque JSON until verified.
package hookio
