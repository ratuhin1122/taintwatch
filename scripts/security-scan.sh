#!/usr/bin/env bash
# Preserve scanner failure status, including missing tools; summarize either way.
set -uo pipefail
scanner=${1:?scanner required}
case "$scanner" in govulncheck|gosec) ;; *) exit 2 ;; esac
report=$(mktemp)
trap 'rm -f -- "$report"' EXIT
args=(./...)
if [[ "$scanner" == gosec ]]; then
    # Local tooling caches are not product source; CI checkouts have none.
    args=(-exclude-dir=.local-tmp -exclude-dir=.go-cache -exclude-dir=dist -exclude-dir=build ./...)
fi
timeout 240s "$scanner" "${args[@]}" > "$report" 2>&1
status=$?
cat "$report"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        printf '### %s (advisory)\n\nExit code: %s (124 means the four-minute limit expired). Findings and scanner errors do not block CI during rollout.\n\n' "$scanner" "$status"
        printf '<details><summary>Report (first 200 lines; full output is in the job log)</summary>\n\n~~~~text\n'
        head -n 200 "$report"
        printf '\n~~~~\n</details>\n\n'
    } >> "$GITHUB_STEP_SUMMARY"
fi
exit "$status"
