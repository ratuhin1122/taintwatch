# Architecture

The scaffold separates the command dispatcher from packages for hook transport,
policy, state, source classification, shell parsing, rules, audit, explanations,
telemetry detectors, tainted-value matching, installation, and evaluation.

Only `internal/hookio` will know Claude Code payload formats. Hook handlers are
currently stubs. `spike/` is an independent throwaway module, excluded from root
Go package discovery. The root module has no third-party dependencies.

The planned boundary is policy plus session state plus attempted action. Content
detection is telemetry only. This is defense-in-depth, not a prompt-injection
solution; coarse session-level taint loses fine-grained provenance.
