# Value provenance (TW009)

PostToolUse extracts indicators only when the loaded source policy classifies the
completed tool as tainting. It scans JSON response string values in document order,
not keys or the request. No specific Read/WebFetch/Bash/MCP result schema is
assumed. URL, DNS-name, IP-address, email-like target and file-path tokens are
stored in the taint event's `value_matches` array with precomputed encodings.
Trusted sources do not add indicators. Old events without this field remain
tainted but cannot retrospectively provide value provenance.

The extractor recognizes URL tokens with a scheme/host, ASCII DNS names, IPv4 and
IPv6 literals, email-like addresses, slash/backslash paths, dotfiles and dotted
names. Dotted names are ambiguous between hosts and filenames. This is a bounded
token heuristic: quoted paths containing spaces, unusual punctuation, IDNs and
arbitrary prose references to filenames are not fully modeled. It does not fetch,
resolve, normalize symlinks or execute anything.

For each original it precomputes standard and URL-safe base64, padded and unpadded;
URL query/path escaping (upper/lower hex escapes) and fully percent-escaped bytes;
upper/lower hex; HTML escaping and fully numeric decimal/hex entities. Base64 also
includes stable interior cores for byte alignment offsets zero, one and two:
unknown boundary sextets are trimmed so an indicator can match inside an encoding
of a larger string. Short IPv6 literals can yield two-character cores. These cores
can collide and are not proof that the complete original was decoded or used.
Nested encoding and arbitrary mixtures of encodings are not covered.

PreToolUse compiles retained patterns into an in-house sparse Aho-Corasick
automaton, with no new dependency. It scans resolved literal Bash arguments,
including wrapper/nested commands exposed by shellparse, extracted shell file
reads/writes and redirection paths, WebFetch's URL, and Read/Write/Edit's file_path.
Separate arguments are scanned separately; values are not synthesized across
argument boundaries. Matching is case-sensitive byte-substring search. There is
no hostname/path boundary claim for a substring match.

A match enables the default ask rule TW009, with the source tool in the reason:
"This argument came from untrusted content read earlier (WebFetch)". The existing
deny/ask/allow precedence and rule order still apply. If another ask wins, its
reason also names the provenance signal. Policy can override TW009 as it can
other rules; project weakening remains guarded. Clean sessions never trigger it.

Bare exact allowlisted hostnames/IPs and origin-only URLs are excluded, including
their encodings. Merely encountering github.com must not taint all later GitHub
arguments. A complete supplied URL with a path/query or an email target remains a
signal even on an allowlisted host. This does not establish destination ownership.

## Bounds and privacy

- Scan the first 1 MiB of response string data; retain at most 32 unique originals
  per event, each 4–256 bytes (valid IP literals may be shorter), and at most 32
  variants per original.
- Consider at most the newest 128 taint events and 64 retained indicators per
  pre-hook, with a total pattern budget of 128 KiB. The automaton has at most one
  node per pattern byte plus its root. Scan at most 1 MiB across action arguments.
  Limits are deterministic; excess data is not covered. Old events remain in
  coarse taint history but can leave this matching window. Existing state-file
  size, retention, hook-input and deadline bounds still apply.
- Extraction and scanning are linear in the bounded input; matching avoids a
  separate search of the argument for every encoding. Pattern construction and
  state serialization have fixed indicator/variant/length budgets.
- Originals and variants may contain sensitive URL parameters or paths. They are
  persisted in mode-0600 session state under a mode-0700 directory. This is new
  retained data, not a redacted audit body. Clear removes session taint events;
  retention can remove state. Protect the state directory accordingly.
- Audit/hook reasons omit matched originals and encodings. Audits retain the rule
  ID, source metadata and existing redacted match snapshot. The replay schema is
  now version 2; older snapshots cannot silently assume TW009 did not match.

## Interpretation

These are exact and enumerated encoded-form matches only. Paraphrased, split or
otherwise transformed values are not detected. A match means an argument shares
bytes with an earlier indicator, not that an instruction was followed. A normal
MCP search result naming a source file can therefore cause a benign confirmation.
The authored benign allow expectation is retained and reported as friction in
[EVAL.md](EVAL.md#measured-results); the eval CI gate remains strict and fails for
that mismatch. Neither labels nor gate semantics are relaxed to hide this cost.
