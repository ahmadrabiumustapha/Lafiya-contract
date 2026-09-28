# Runbook: Revoking All Attestations by a Fraudulent Attester

**Audience:** Lafiya registry admin responding to a fraudulent or compromised CHW.

**Scope:** Bulk-revoking all attestations submitted by a specific attester address,
discovered via `AttestationRecorded` event enumeration.

**Reference:** GitHub issue #400, ADR-0006 (attestation revocation semantics).

---

## Background

When a community health worker (CHW) is found to be fraudulent or their key is
compromised, all attestations they submitted must be revoked. The on-chain contract
only exposes `revoke_attestation(record_hash)` — one hash per call. There is no
on-chain index from attester to hashes.

`lafiya-cli attestation revoke-by-attester` automates:

1. Enumerating `AttestationRecorded` events for the attester via `getEvents` (RPC).
2. Detecting if the requested range is outside RPC event retention (≈7 days).
3. Deduplicating record hashes.
4. Checking current state (skipping already-revoked hashes).
5. Warning on collateral damage: hashes that also have attestations from other
   valid attesters. Revocation is all-or-nothing per hash.
6. Executing with a confirmation prompt, per-hash journal, and poll-before-retry.
7. Writing a CSV or JSON audit report.

---

## Prerequisites

- Admin identity configured: `stellar keys show admin-identity`
- Network config in `config/networks.toml` with contract IDs set
- `lafiya-cli` installed: `cargo install --path crates/lafiya-cli`

---

## Step 1: Dry run — enumerate and plan

Always run with `--dry-run` first to review the plan before executing.

```bash
lafiya-cli --network testnet attestation revoke-by-attester \
  GFRAUDULENT...ATTESTERADDRESS \
  --dry-run \
  --audit-report /tmp/revoke-plan.json
```

Review `/tmp/revoke-plan.json`. Check:
- `total_hashes`: is the count expected?
- `collateral_damage_warnings`: are any valid attesters co-signing these hashes?
  If so, decide whether to proceed — revoking will remove their attestations too.
- `hashes`: spot-check a few entries against the patient record IDs you expect.

---

## Step 2: Execute revocations

```bash
lafiya-cli --network testnet attestation revoke-by-attester \
  GFRAUDULENT...ATTESTERADDRESS \
  --source admin-identity \
  --audit-report /tmp/revoke-executed.json
```

The CLI will:
1. Re-run preflight checks (passphrase match, ledger freshness, contract identity).
2. Display the revocation plan with any collateral damage warnings.
3. Ask for confirmation: `Proceed with revoking N hashes? [y/N]`.
4. Execute revocations one by one with a progress journal.
5. Report successes and failures.
6. Write the audit report.

---

## Step 3: Verify

```bash
# Check a specific hash to confirm revocation
lafiya-cli --network testnet attestation get <record_hash>
```

A revoked hash should return no attestation or a revoked state.

---

## Scoped time window

If the attester has been operating for more than the RPC retention window
(≈7 days, ≈120,960 ledgers), the full event range may not be available:

```bash
# --since-ledger 0 means "from the oldest retained ledger"
lafiya-cli --network testnet attestation revoke-by-attester \
  GFRAUDULENT...ATTESTERADDRESS \
  --since-ledger 1000000 \
  --until-ledger 1100000 \
  --dry-run
```

If the range falls outside retention, the CLI aborts with:

```
since_ledger N is outside the RPC event retention window.
Oldest retained ledger (approx): M
...
Remediation: set --since-ledger to at least M or use an event indexer.
```

> **Never** trust partial results as complete. If the full history is needed,
> use an event indexer (e.g. a hosted indexer or a local quickstart node with
> full ledger history).

---

## Collateral damage

Revocation in the attestation-registry is all-or-nothing per hash. If a hash has
attestations from multiple valid attesters, revoking it also removes theirs.

The CLI warns explicitly:

```
⚠ COLLATERAL DAMAGE WARNING
The following hashes also have attestations from OTHER attesters.
Revoking these will remove ALL attestations for the hash...

  Hash: <hash>
        Co-attester: GOTHER...ATTESTER
```

Before proceeding, verify the co-attesters' attestations are also invalid, or
exclude those hashes from the revocation by narrowing the time window.

---

## Audit trail

Always archive the audit report after execution:

```bash
# JSON format
lafiya-cli ... --audit-report /path/to/revoke-YYYYMMDD-ATTESTER.json

# CSV format
lafiya-cli ... --audit-report /path/to/revoke-YYYYMMDD-ATTESTER.csv
```

Archive in the incident response record along with:
- The fraudulent attester's address
- The date range of their attestations
- The list of affected patient record hashes (never the patient data itself)
- The admin key identity used for revocation

---

## After revocation

1. Remove the fraudulent attester from the allowlist (if still listed):
   ```bash
   lafiya-cli --network testnet attester remove GFRAUDULENT...ATTESTERADDRESS \
     --source admin-identity
   ```

2. Notify `lafiya-web` to re-display affected records as unverified.
   The public emergency pages for these hashes will now show no verified indicator.

3. Document in the incident report and open a follow-up in `lafiya-docs`.
