#!/bin/sh
# Compatibility entry point: generate the same unsigned artifacts as CI.
# This never publishes or signs a release. Requires GoReleaser and Syft on PATH.
set -eu
exec goreleaser release --snapshot --clean
