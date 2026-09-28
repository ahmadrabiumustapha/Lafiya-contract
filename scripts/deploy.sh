#!/usr/bin/env bash
# DEPRECATED: This script is a thin compatibility wrapper.
# Use `lafiya-cli deploy` instead. This wrapper will be removed in the next release.
#
# Migration:
#   lafiya-cli --network testnet deploy --source <identity> --admin <address>
#   lafiya-cli --network testnet deploy --dry-run
#   lafiya-cli --network testnet deploy --build-only

echo "⚠  DEPRECATED: scripts/deploy.sh is a compatibility wrapper." >&2
echo "   Use: lafiya-cli deploy [options]" >&2
echo "   Run: lafiya-cli deploy --help  for all options." >&2
echo "" >&2

exec lafiya-cli deploy "$@"
