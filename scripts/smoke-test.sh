#!/usr/bin/env bash
# DEPRECATED: This script is a thin compatibility wrapper.
# Use `lafiya-cli smoke-test` instead. This wrapper will be removed in the next release.
#
# Migration:
#   lafiya-cli --network testnet smoke-test --source <identity>
#   lafiya-cli smoke-test --help  for all options.

echo "⚠  DEPRECATED: scripts/smoke-test.sh is a compatibility wrapper." >&2
echo "   Use: lafiya-cli smoke-test [options]" >&2
echo "   Run: lafiya-cli smoke-test --help  for all options." >&2
echo "" >&2

exec lafiya-cli smoke-test "$@"
