# Encoded-content telemetry

PostToolUse runs `internal/detect/encoded` on response string values only when
the source classifier marks that completed tool as tainting. It uses the same
bounded string prefix as hidden-content telemetry. It does not scan prompt text,
tool requests or response keys, or make assumptions about a tool-result schema.
A previously tainted session does not cause every subsequent clean source to be
scanned.

The scanner recognizes contiguous base64-looking and hex-looking ASCII tokens.
It decodes exactly one level: standard or URL-safe base64, with or without legal
padding, or even-length hex (optionally prefixed with `0x`). A token that qualifies
as hex is not retried as base64. Invalid candidates and non-printable/non-UTF-8
decoded data produce no content hints (Unicode formatting characters are allowed
in otherwise textual data). No command is executed, fetched or loaded.

Known shape exclusions are image data URIs, sha512-/sha256- integrity tokens,
three-part JWT-shaped tokens, UUIDs, and bare hexadecimal Git object IDs with
SHA-1/SHA-256 lengths. Plain or decoded JSON source-map text with version, sources
and mappings fields is skipped; inline JSON source-map data URIs identified by
sourceMappingURL are skipped before decoding. Structural lookalikes can evade
telemetry: these exclusions do not authenticate benignness. Split structural JSON
objects cannot always be recognized after response string extraction.

Only printable decoded text receives the informational checks:

- Instruction-like phrases from a fixed list, such as "ignore previous
  instructions", "do not ask", "system prompt" and "execute this command".
- Common secret-path mentions, including dotenv files, private keys, cloud/SSH
  configuration, credentials files, Terraform state and shell histories. This is
  a fixed lexical heuristic, not policy-aware filesystem access analysis.
- URLs recognized by the bounded value extractor.
- Decode/download-and-run shapes analyzed by the existing shell AST detector.
  Prose or unsupported syntax can prevent this check from recognizing a shape.

Hints aggregate the encoding, heuristic type and number of decoded blobs that
matched that type. Multiple phrases in one blob count once for that type. The
audit's optional `encoded` report also records candidate/decoded/text counts,
decoded-byte count, skipped shapes and reached limits. Neither the original blob
nor its decoded body, URLs, paths or secret values are copied into these findings.
`explain` shows them as informational, with counts and scan-limit notices.

## Hard bounds and non-goals

The scanner examines at most the first 1 MiB, considers at most 32 decoding
candidates, and skips whole blobs larger than 16 KiB. The minimum blob length is
eight encoded characters. A blob cut by the input-prefix limit is not decoded.
There is a 64 KiB total decoding budget, reserved before decoding; invalid
candidates consume their reservation too. At most eight encoding/type aggregates
can be retained. Decoding, lexical scans and fixed RE2 checks have bounded input;
shell analysis retains its existing independent traversal bounds.

There is no recursive decoding, decompression, decryption, execution or semantic
instruction detection. Short or wrapped blobs, unsupported encodings, large data,
binary text, escaped/mixed forms and data beyond a budget can be missed. Ordinary
encoded documentation can mention security terms and produce hints. Absence of
hints is not evidence of safety.

This telemetry never selects a rule, emits a permission decision, modifies
post-hook context, or promotes decoded values into taint events/value matching.
The source's existing taint classification still applies independently. The
existing hook failure/deadline machinery remains in force.

## Measurement

The unchanged synthetic benign corpus is not a labeled set of encoded negative
controls. Interpret its observed response-level flag rate alongside the decoded
blob/text counts and scan limits. The dated, versioned numbers, denominator,
decoded counts and reproduction command are in
[EVAL.md](EVAL.md#measured-results). Known-shape and decoded-benign unit controls
exercise those cases separately; they are not counted as extra corpus sessions.
