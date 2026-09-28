#!/usr/bin/env bash
# DEPRECATED: This script is a thin compatibility wrapper.
# Use `lafiya-cli attester` and `lafiya-cli attestation` subcommands instead.
# This wrapper will be removed in the next release.
#
# Migration:
#   lafiya-cli --network testnet attester add <address> --source <identity>
#   lafiya-cli --network testnet attester remove <address> --source <identity>
#   lafiya-cli --network testnet attester is <address>
#   lafiya-cli --network testnet attestation get <hash>

echo "⚠  DEPRECATED: scripts/admin.sh is a compatibility wrapper." >&2
echo "   Use: lafiya-cli attester <subcommand>  or  lafiya-cli attestation <subcommand>" >&2
echo "   Run: lafiya-cli --help  for all options." >&2
echo "" >&2

exec lafiya-cli "$@"
