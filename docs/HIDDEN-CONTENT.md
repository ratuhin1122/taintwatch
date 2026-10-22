# Hidden-content telemetry

PostToolUse scans response string values only when the existing source policy
classifies that tool result as untrusted. Merely having a tainted session does
not turn an otherwise trusted response into an untrusted source. Trusted MCP
servers and ordinary balanced-profile reads retain their existing treatment.

`internal/detect/hidden` reports hints, **never permission decisions**. It does
not add taint events, modify rule actions, inject instructions into additional
context, or execute/render returned content. Post-hook output stays the same
with or without findings. The existing source classifier still controls taint.

Response variants remain opaque: `hookio.ResponseText` walks JSON string values
in document order, excluding property names and separating values with newlines.
No particular Read, WebFetch, Bash, or MCP result schema is assumed. Actual live
response captures remain pending as recorded in ASSUMPTIONS.md.

The first 1 MiB of extracted UTF-8 text (including separators) is examined.
Incomplete trailing UTF-8 is omitted at that boundary. Audit records include
`hidden.bytes_scanned`, `hidden.truncated`, and `hidden.findings`. Each finding
has `type`, aggregated `count`, and the first short safe `excerpt`. Counts apply
only to that prefix. `explain` displays the hints as informational; `--json`
includes the same structured report. Previously written records remain readable.

Types:

| Type | Hint |
| --- | --- |
| `zero-width` | U+200B, U+200C, U+200D, U+2060, U+FEFF; emoji-context ZWJ excluded |
| `bidi-control` | U+202A–202E and U+2066–2069 |
| `unicode-tag` | Tags block U+E0000–E007F; ordinary England/Scotland/Wales emoji flag sequences excluded |
| `homoglyph` | A word containing Latin letters plus at least two common Greek/Cyrillic Latin lookalikes making up at least a third of its letters |
| `html-comment` | HTML comment opening markers, including unclosed comments |
| `hidden-style` | Literal CSS `display:none` or `visibility:hidden` declarations |
| `white-on-white` | Literal white foreground and white background declarations in one quoted style attribute or CSS declaration block |
| `small-font` | Zero size, sub-pixel sizes, 1–5 px/pt, below 0.5 em/rem, or 1–under-6 percent size hints |
| `markdown-link-mismatch` | Inline Markdown link label differs from its literal destination |

Excerpts never copy hidden bodies or URLs. Character hints show codepoints such
as `<U+200B>`; mixed-script words show up to four lookalike codepoints without
copying the word. Markup hints use structural summaries and style hints use
bounded matched declarations. Audit redaction runs before storage, and control
characters are rendered visibly. Whole tool contents are never written to audit.

This is a presentation heuristic, not proof of prompt injection. Descriptive
Markdown links deliberately differ from their destinations and will be reported.
Invisible controls can have legitimate language uses. Ordinary CJK text, emoji
joiners, skin-tone sequences, and regional flags have regression tests. Emoji
context is a bounded pictographic-range heuristic, not a full Unicode grapheme
segmenter. The homoglyph heuristic is intentionally not a full confusables table
and does not label ordinary single-script Greek or Cyrillic words.

No HTML/CSS layout engine or CommonMark parser runs: computed/inherited CSS,
CSS escapes, encoded entities, reference links, and rendered visibility are not
resolved. Literal examples inside code can also produce informational hints.
All scanning uses a fixed number of linear passes, RE2 regular expressions,
monotonically advancing parsers, and at most nine aggregate finding types.
Memory and scan work are bounded by the prefix cap. Hook input decoding retains
its separate 8 MiB limit and existing timeout. Corpus-level precision measurement
is deferred to M3; the unit cases are not a false-positive-rate measurement.
