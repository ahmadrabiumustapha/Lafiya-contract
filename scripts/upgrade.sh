#!/usr/bin/env bash
# DEPRECATED: This script is a thin compatibility wrapper.
# Use `lafiya-cli upgrade` instead. This wrapper will be removed in the next release.
#
# Migration:
#   lafiya-cli --network testnet upgrade --contract attester-registry --source <identity>
#   lafiya-cli upgrade --help  for all options.

echo "⚠  DEPRECATED: scripts/upgrade.sh is a compatibility wrapper." >&2
echo "   Use: lafiya-cli upgrade [options]" >&2
echo "   Run: lafiya-cli upgrade --help  for all options." >&2
echo "" >&2

exec lafiya-cli upgrade "$@"
