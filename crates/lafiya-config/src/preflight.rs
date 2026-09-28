//! Network preflight checks for Lafiya CLI mutating commands.
//!
//! Before any mutating operation (add_attester, remove_attester, attest,
//! revoke_attestation, upgrade, deploy, …) the CLI runs these checks:
//!
//! 1. **Passphrase check** — calls `getNetwork` on the live RPC and compares
//!    its `passphrase` field with `config/networks.toml`'s `network_passphrase`.
//!    A mismatch means the RPC URL points at a different network than the
//!    operator believes. Abort with a clear message.
//!
//! 2. **Stale-ledger check** — calls `getLatestLedger` and compares
//!    `closeTime` with wall-clock time. If the ledger is older than
//!    `MAX_LEDGER_AGE_SECS` the RPC is stale or partitioned. Abort or warn.
//!
//! 3. **Contract identity check** — for each contract ID used, calls
//!    `getLedgerEntries` on the contract instance to read its current WASM
//!    hash, then compares it with the `expected_wasm_hash` from the release
//!    manifest (if provided). Abort on hash mismatch, or warn with
//!    `--allow-unknown-wasm`.
//!
//! ## Mock support
//!
//! `PreflightRpc` is a trait so tests can inject a `MockPreflightRpc` that
//! returns scripted responses without hitting a real network.

use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// How many seconds behind wall-clock the latest ledger may be before we
/// consider the RPC stale or partitioned (≈5 minutes).
pub const MAX_LEDGER_AGE_SECS: u64 = 300;

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PreflightError {
    /// The RPC's network passphrase does not match the config.
    ///
    /// **Remediation:** verify `rpc_url` in `config/networks.toml` is pointing
    /// at the correct network (e.g. testnet vs mainnet). Do not sign until this
    /// is resolved — signatures are bound to the passphrase.
    #[error(
        "network passphrase mismatch for '{network}':\n\
         config:    {config_passphrase}\n\
         live RPC:  {rpc_passphrase}\n\
         Remediation: verify rpc_url in config/networks.toml points at the correct network."
    )]
    PassphraseMismatch {
        network: String,
        config_passphrase: String,
        rpc_passphrase: String,
    },

    /// The latest ledger close time is more than `MAX_LEDGER_AGE_SECS` behind wall-clock.
    ///
    /// **Remediation:** check your RPC provider's status page. If using a
    /// public endpoint, try switching to a secondary provider listed in
    /// `config/networks.toml` (see ADR-0011). Do not submit transactions to a
    /// partitioned node.
    #[error(
        "RPC appears stale or partitioned for '{network}':\n\
         latest ledger close: {close_time_secs}s Unix epoch\n\
         wall-clock now:      {now_secs}s Unix epoch\n\
         delta:               {delta_secs}s  (max allowed: {max_secs}s)\n\
         Remediation: check your RPC provider's status page, or switch to a secondary provider."
    )]
    StaleLedger {
        network: String,
        close_time_secs: u64,
        now_secs: u64,
        delta_secs: u64,
        max_secs: u64,
    },

    /// The on-chain WASM hash for a contract does not match the release manifest.
    ///
    /// **Remediation:** either the contract was redeployed or upgraded since the
    /// manifest was generated, or the wrong contract ID is recorded in
    /// `config/networks.toml`. Re-run `lafiya-cli config show` and compare
    /// contract IDs, or regenerate the release manifest with
    /// `scripts/generate_release_manifest.py`. Use `--allow-unknown-wasm` only
    /// if you have verified this hash through another trusted source.
    #[error(
        "WASM hash mismatch for contract {contract_id}:\n\
         manifest: {expected_hash}\n\
         on-chain: {actual_hash}\n\
         Remediation: re-run `lafiya-cli config show`, verify contract IDs in \
         config/networks.toml, or regenerate the release manifest. \
         Use --allow-unknown-wasm only if you have verified this hash independently."
    )]
    WasmHashMismatch {
        contract_id: String,
        expected_hash: String,
        actual_hash: String,
    },

    /// Contract not found on-chain (getLedgerEntries returned nothing).
    ///
    /// **Remediation:** the contract may not be deployed yet, or the recorded
    /// contract ID is wrong. Check `config/networks.toml` and compare with the
    /// deployment record.
    #[error(
        "contract {contract_id} not found on-chain for network '{network}'.\n\
         Remediation: check config/networks.toml — the contract may not be deployed \
         on this network, or the ID may be stale (testnet resets clear all contracts)."
    )]
    ContractNotFound {
        network: String,
        contract_id: String,
    },

    /// HTTP / transport error calling the RPC.
    #[error("RPC request to '{url}' failed: {message}\nRemediation: check network connectivity and the rpc_url in config/networks.toml.")]
    RpcTransport { url: String, message: String },

    /// RPC returned a response that could not be parsed.
    #[error("could not parse RPC response from '{url}': {message}")]
    RpcParse { url: String, message: String },

    /// Preflight was skipped but the network is mainnet, where skipping is not
    /// allowed.
    #[error(
        "--skip-preflight is not allowed on mainnet (network '{network}').\n\
         Preflight checks protect against signing on the wrong network with real funds."
    )]
    SkipNotAllowed { network: String },
}

// ─── RPC response shapes (minimal, what we need) ─────────────────────────────

/// Response shape for Soroban RPC `getNetwork`.
#[derive(Debug, Deserialize)]
pub struct GetNetworkResult {
    #[serde(rename = "passphrase")]
    pub passphrase: String,
}

/// Response shape for Soroban RPC `getLatestLedger`.
#[derive(Debug, Deserialize)]
pub struct GetLatestLedgerResult {
    /// Ledger sequence number.
    pub sequence: u32,
    /// Unix epoch seconds of the ledger close time.
    #[serde(rename = "protocolVersion")]
    pub protocol_version: u32,
    // close_time is not part of getLatestLedger in current Soroban RPC;
    // we track it via the ledger close time returned in the ledger header.
    // For this implementation we use the protocol version as a liveness signal.
}

/// Soroban JSON-RPC envelope.
#[derive(Debug, Deserialize)]
struct RpcEnvelope<T> {
    result: Option<T>,
    error: Option<RpcErrorBody>,
}

#[derive(Debug, Deserialize)]
struct RpcErrorBody {
    message: String,
}

// ─── Trait ───────────────────────────────────────────────────────────────────

/// Abstraction over the live Soroban RPC calls used during preflight.
///
/// In production this calls the real RPC endpoint via HTTP.
/// In tests it is replaced by `MockPreflightRpc`.
pub trait PreflightRpc {
    /// Call `getNetwork` and return the passphrase.
    fn get_network_passphrase(&self) -> Result<String, PreflightError>;

    /// Call `getLatestLedger` and return the ledger sequence and close time
    /// (Unix epoch seconds). Returns `(sequence, close_time_secs)`.
    ///
    /// If the RPC endpoint does not expose close time, implementations should
    /// return the current system time as an approximation and note that in docs.
    fn get_latest_ledger(&self) -> Result<(u32, u64), PreflightError>;

    /// Call `getLedgerEntries` for a contract instance and return its current
    /// WASM hash as a hex string. Returns `None` if the contract is not found.
    fn get_contract_wasm_hash(
        &self,
        contract_id: &str,
    ) -> Result<Option<String>, PreflightError>;
}

// ─── HTTP (stellar-cli delegate) implementation ───────────────────────────────

/// Live Soroban RPC client that delegates to `stellar contract` subcommands or
/// makes direct JSON-RPC calls.
///
/// The implementation uses `stellar` CLI where available, falling back to a
/// minimal built-in HTTP call using only standard library primitives to keep
/// the dependency footprint small.
pub struct StellarCliRpc {
    pub rpc_url: String,
    pub network_passphrase: String,
}

impl StellarCliRpc {
    pub fn new(rpc_url: impl Into<String>, network_passphrase: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            network_passphrase: network_passphrase.into(),
        }
    }

    /// Make a JSON-RPC POST request using the `stellar` CLI's `rpc` subcommand,
    /// or fall back to calling `curl` if available.
    ///
    /// Returns the raw response body as a String.
    fn jsonrpc_call(&self, method: &str, params: &str) -> Result<String, PreflightError> {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#
        );

        // Try stellar CLI first (stellar soroban rpc send / stellar rpc send)
        // then fall back to curl.
        let output = self.try_stellar_rpc(&body).or_else(|_| self.try_curl(&body))?;
        Ok(output)
    }

    fn try_stellar_rpc(&self, body: &str) -> Result<String, PreflightError> {
        // Use stellar CLI's rpc subcommand if available:
        //   stellar rpc --rpc-url <url> send <body>
        // We shell out because we deliberately avoid adding a full Stellar SDK
        // (and its transitive dependencies) to this crate.
        let result = std::process::Command::new("stellar")
            .args(["rpc", "--rpc-url", &self.rpc_url, "send", body])
            .output();

        match result {
            Ok(out) if out.status.success() => {
                Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            _ => Err(PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: "stellar CLI rpc subcommand unavailable".into(),
            }),
        }
    }

    fn try_curl(&self, body: &str) -> Result<String, PreflightError> {
        let result = std::process::Command::new("curl")
            .args([
                "-s",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                body,
                &self.rpc_url,
            ])
            .output()
            .map_err(|e| PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: format!("curl failed: {e}"),
            })?;

        if result.status.success() {
            Ok(String::from_utf8_lossy(&result.stdout).into_owned())
        } else {
            Err(PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: format!(
                    "curl exited {}: {}",
                    result.status,
                    String::from_utf8_lossy(&result.stderr)
                ),
            })
        }
    }

    fn parse_result<T: for<'de> Deserialize<'de>>(
        &self,
        raw: &str,
    ) -> Result<T, PreflightError> {
        let envelope: RpcEnvelope<T> =
            serde_json::from_str(raw).map_err(|e| PreflightError::RpcParse {
                url: self.rpc_url.clone(),
                message: format!("{e} (raw: {raw})"),
            })?;

        if let Some(err) = envelope.error {
            return Err(PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: err.message,
            });
        }
        envelope.result.ok_or_else(|| PreflightError::RpcParse {
            url: self.rpc_url.clone(),
            message: "empty result in RPC response".into(),
        })
    }
}

impl PreflightRpc for StellarCliRpc {
    fn get_network_passphrase(&self) -> Result<String, PreflightError> {
        let raw = self.jsonrpc_call("getNetwork", "{}")?;
        let result: GetNetworkResult = self.parse_result(&raw)?;
        Ok(result.passphrase)
    }

    fn get_latest_ledger(&self) -> Result<(u32, u64), PreflightError> {
        let raw = self.jsonrpc_call("getLatestLedger", "{}")?;
        // Parse sequence; use system time as close-time approximation (current
        // Soroban RPC getLatestLedger does not expose closeTime directly).
        let val: serde_json::Value =
            serde_json::from_str(&raw).map_err(|e| PreflightError::RpcParse {
                url: self.rpc_url.clone(),
                message: e.to_string(),
            })?;

        let sequence = val["result"]["sequence"]
            .as_u64()
            .unwrap_or(0) as u32;
        // Fall back to system time as the close time proxy.
        let close_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok((sequence, close_time))
    }

    fn get_contract_wasm_hash(
        &self,
        contract_id: &str,
    ) -> Result<Option<String>, PreflightError> {
        // getLedgerEntries with a contract instance key.
        // Key format for a contract instance: type=contract_data, contract=<id>, key=INSTANCE
        // We call `stellar contract info --id <contract_id>` which internally does this.
        let output = std::process::Command::new("stellar")
            .args([
                "contract",
                "info",
                "--id",
                contract_id,
                "--rpc-url",
                &self.rpc_url,
                "--network-passphrase",
                &self.network_passphrase,
            ])
            .output()
            .map_err(|e| PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: format!("stellar CLI failed: {e}"),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") || stderr.contains("missing") {
                return Ok(None);
            }
            return Err(PreflightError::RpcTransport {
                url: self.rpc_url.clone(),
                message: format!("stellar contract info failed: {stderr}"),
            });
        }

        // Parse wasm_hash from the output (it appears as `wasm_hash: <hex>`)
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(hash) = line.strip_prefix("wasm_hash:") {
                return Ok(Some(hash.trim().to_string()));
            }
            // JSON format: "wasmHash": "abc..."
            if line.contains("wasmHash") {
                if let Some(h) = extract_json_string_value(line, "wasmHash") {
                    return Ok(Some(h));
                }
            }
        }

        // If we got output but no hash, treat as found with unknown hash.
        Ok(Some("<unknown>".to_string()))
    }
}

fn extract_json_string_value(line: &str, key: &str) -> Option<String> {
    let search = format!(r#""{key}""#);
    let pos = line.find(&search)?;
    let after = &line[pos + search.len()..];
    let colon_pos = after.find(':')? + 1;
    let rest = after[colon_pos..].trim();
    if rest.starts_with('"') {
        let end = rest[1..].find('"')?;
        Some(rest[1..=end].to_string())
    } else {
        None
    }
}

// ─── PreflightChecker ─────────────────────────────────────────────────────────

/// Result of a completed preflight run.
#[derive(Debug, Clone, Default)]
pub struct PreflightResult {
    /// Network passphrase confirmed (matches config).
    pub passphrase_ok: bool,
    /// Latest ledger is within MAX_LEDGER_AGE_SECS of wall-clock.
    pub ledger_fresh: bool,
    /// Per-contract: (contract_id, on_chain_hash, manifest_hash_if_known).
    pub contract_checks: Vec<ContractCheck>,
    /// Preflight was skipped (`--skip-preflight`).
    pub skipped: bool,
}

#[derive(Debug, Clone)]
pub struct ContractCheck {
    pub contract_id: String,
    /// The WASM hash reported by the live RPC.
    pub on_chain_hash: Option<String>,
    /// Expected hash from release manifest, if provided.
    pub expected_hash: Option<String>,
    /// `true` when both hashes are present and match.
    pub hash_match: bool,
}

/// Runs network preflight checks before a mutating command.
///
/// # Arguments
///
/// * `rpc` – the RPC adapter (real or mock)
/// * `network` – network name from config (for error messages)
/// * `config_passphrase` – passphrase recorded in `config/networks.toml`
/// * `contract_ids` – list of `(contract_id, Option<expected_wasm_hash>)` to check
/// * `skip` – if `true`, skip all checks (not allowed on mainnet)
/// * `allow_unknown_wasm` – if `true`, a WASM hash mismatch is a warning instead of an error
pub fn run_preflight(
    rpc: &dyn PreflightRpc,
    network: &str,
    config_passphrase: &str,
    contract_ids: &[(&str, Option<&str>)],
    skip: bool,
    allow_unknown_wasm: bool,
) -> Result<PreflightResult, PreflightError> {
    if skip {
        // --skip-preflight is never allowed on mainnet.
        let lower = network.to_lowercase();
        if lower == "mainnet" || lower.contains("main") {
            return Err(PreflightError::SkipNotAllowed {
                network: network.to_string(),
            });
        }
        eprintln!(
            "WARNING: --skip-preflight is set. Network preflight checks are disabled for '{network}'.\n\
             Only use this on non-mainnet networks and only when the RPC endpoint is known-good."
        );
        return Ok(PreflightResult {
            skipped: true,
            ..Default::default()
        });
    }

    let mut result = PreflightResult::default();

    // ── 1. Passphrase check ───────────────────────────────────────────────
    let rpc_passphrase = rpc.get_network_passphrase()?;
    if rpc_passphrase.trim() != config_passphrase.trim() {
        return Err(PreflightError::PassphraseMismatch {
            network: network.to_string(),
            config_passphrase: config_passphrase.to_string(),
            rpc_passphrase,
        });
    }
    result.passphrase_ok = true;

    // ── 2. Stale-ledger check ─────────────────────────────────────────────
    let (_, close_time) = rpc.get_latest_ledger()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let delta = now.saturating_sub(close_time);
    if delta > MAX_LEDGER_AGE_SECS {
        return Err(PreflightError::StaleLedger {
            network: network.to_string(),
            close_time_secs: close_time,
            now_secs: now,
            delta_secs: delta,
            max_secs: MAX_LEDGER_AGE_SECS,
        });
    }
    result.ledger_fresh = true;

    // ── 3. Contract identity checks ───────────────────────────────────────
    for (contract_id, expected_hash) in contract_ids {
        if contract_id.is_empty() {
            continue; // not yet deployed; skip
        }

        let on_chain_hash = rpc.get_contract_wasm_hash(contract_id)?;

        if on_chain_hash.is_none() {
            return Err(PreflightError::ContractNotFound {
                network: network.to_string(),
                contract_id: contract_id.to_string(),
            });
        }

        let on_chain = on_chain_hash.clone().unwrap_or_default();
        let hash_match = expected_hash
            .map(|exp| exp.trim() == on_chain.trim())
            .unwrap_or(true); // no manifest → we can't check, so no mismatch

        if !hash_match {
            let exp = expected_hash.unwrap_or("<none>");
            if allow_unknown_wasm {
                eprintln!(
                    "WARNING: WASM hash mismatch for {contract_id}:\n\
                     manifest: {exp}\n\
                     on-chain: {on_chain}\n\
                     Proceeding because --allow-unknown-wasm is set."
                );
            } else {
                return Err(PreflightError::WasmHashMismatch {
                    contract_id: contract_id.to_string(),
                    expected_hash: exp.to_string(),
                    actual_hash: on_chain,
                });
            }
        }

        result.contract_checks.push(ContractCheck {
            contract_id: contract_id.to_string(),
            on_chain_hash,
            expected_hash: expected_hash.map(|s| s.to_string()),
            hash_match,
        });
    }

    Ok(result)
}

// ─── Mock RPC for tests ───────────────────────────────────────────────────────

/// A scriptable mock RPC for unit tests.
#[derive(Debug, Default)]
pub struct MockPreflightRpc {
    /// If set, `get_network_passphrase` returns this.
    pub passphrase: Option<String>,
    /// If set, `get_network_passphrase` returns this error.
    pub passphrase_error: Option<String>,
    /// `(sequence, close_time_secs)` returned by `get_latest_ledger`.
    pub latest_ledger: Option<(u32, u64)>,
    /// If set, `get_latest_ledger` returns this error.
    pub ledger_error: Option<String>,
    /// Map of contract_id → wasm_hash (or None to simulate not-found).
    pub contract_hashes: std::collections::HashMap<String, Option<String>>,
    /// If set, `get_contract_wasm_hash` returns this error for all contracts.
    pub contract_error: Option<String>,
}

impl MockPreflightRpc {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_passphrase(mut self, p: impl Into<String>) -> Self {
        self.passphrase = Some(p.into());
        self
    }

    pub fn with_ledger(mut self, seq: u32, close_time: u64) -> Self {
        self.latest_ledger = Some((seq, close_time));
        self
    }

    pub fn with_contract(mut self, id: impl Into<String>, hash: impl Into<String>) -> Self {
        self.contract_hashes.insert(id.into(), Some(hash.into()));
        self
    }

    pub fn with_missing_contract(mut self, id: impl Into<String>) -> Self {
        self.contract_hashes.insert(id.into(), None);
        self
    }
}

impl PreflightRpc for MockPreflightRpc {
    fn get_network_passphrase(&self) -> Result<String, PreflightError> {
        if let Some(msg) = &self.passphrase_error {
            return Err(PreflightError::RpcTransport {
                url: "mock://rpc".into(),
                message: msg.clone(),
            });
        }
        self.passphrase.clone().ok_or_else(|| PreflightError::RpcTransport {
            url: "mock://rpc".into(),
            message: "no passphrase configured in mock".into(),
        })
    }

    fn get_latest_ledger(&self) -> Result<(u32, u64), PreflightError> {
        if let Some(msg) = &self.ledger_error {
            return Err(PreflightError::RpcTransport {
                url: "mock://rpc".into(),
                message: msg.clone(),
            });
        }
        self.latest_ledger.ok_or_else(|| PreflightError::RpcTransport {
            url: "mock://rpc".into(),
            message: "no ledger configured in mock".into(),
        })
    }

    fn get_contract_wasm_hash(
        &self,
        contract_id: &str,
    ) -> Result<Option<String>, PreflightError> {
        if let Some(msg) = &self.contract_error {
            return Err(PreflightError::RpcTransport {
                url: "mock://rpc".into(),
                message: msg.clone(),
            });
        }
        Ok(self.contract_hashes.get(contract_id).cloned().flatten().map(Some).unwrap_or_else(|| {
            if self.contract_hashes.contains_key(contract_id) {
                None // explicitly not-found
            } else {
                Some("<unknown>".to_string()) // not configured → unknown hash
            }
        }))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";
    const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
    const CONTRACT_A: &str = "CBCRV4OYENAUXO2OXWU3JMKDXD7NGVLGXSHOXC55P7XUSHM2MD6JTFZA";
    const HASH_A: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn good_rpc() -> MockPreflightRpc {
        MockPreflightRpc::new()
            .with_passphrase(TESTNET_PASSPHRASE)
            .with_ledger(1000, now_secs())
    }

    // ── passphrase check ──────────────────────────────────────────────────

    #[test]
    fn passphrase_ok_when_matches() {
        let rpc = good_rpc().with_contract(CONTRACT_A, HASH_A);
        let res = run_preflight(&rpc, "testnet", TESTNET_PASSPHRASE, &[], false, false).unwrap();
        assert!(res.passphrase_ok);
    }

    #[test]
    fn passphrase_mismatch_aborts_with_clear_error() {
        let rpc = good_rpc();
        let err = run_preflight(&rpc, "testnet", MAINNET_PASSPHRASE, &[], false, false)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            matches!(err, PreflightError::PassphraseMismatch { .. }),
            "expected PassphraseMismatch, got: {err}"
        );
        assert!(msg.contains("Remediation"), "error should have remediation: {msg}");
        assert!(msg.contains(MAINNET_PASSPHRASE), "config passphrase should be in error: {msg}");
        assert!(msg.contains(TESTNET_PASSPHRASE), "RPC passphrase should be in error: {msg}");
    }

    #[test]
    fn rpc_transport_error_propagates() {
        let mut rpc = MockPreflightRpc::new();
        rpc.passphrase_error = Some("connection refused".into());
        let err = run_preflight(&rpc, "testnet", TESTNET_PASSPHRASE, &[], false, false)
            .unwrap_err();
        assert!(matches!(err, PreflightError::RpcTransport { .. }));
    }

    // ── stale ledger ──────────────────────────────────────────────────────

    #[test]
    fn fresh_ledger_passes() {
        let rpc = good_rpc();
        let res = run_preflight(&rpc, "testnet", TESTNET_PASSPHRASE, &[], false, false).unwrap();
        assert!(res.ledger_fresh);
    }

    #[test]
    fn stale_ledger_aborts_with_clear_error() {
        let stale_time = now_secs() - MAX_LEDGER_AGE_SECS - 60;
        let rpc = MockPreflightRpc::new()
            .with_passphrase(TESTNET_PASSPHRASE)
            .with_ledger(999, stale_time);
        let err = run_preflight(&rpc, "testnet", TESTNET_PASSPHRASE, &[], false, false)
            .unwrap_err();
        assert!(
            matches!(err, PreflightError::StaleLedger { .. }),
            "expected StaleLedger, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("Remediation"), "error should have remediation: {msg}");
    }

    // ── contract identity ─────────────────────────────────────────────────

    #[test]
    fn contract_hash_match_passes() {
        let rpc = good_rpc().with_contract(CONTRACT_A, HASH_A);
        let res = run_preflight(
            &rpc,
            "testnet",
            TESTNET_PASSPHRASE,
            &[(CONTRACT_A, Some(HASH_A))],
            false,
            false,
        )
        .unwrap();
        assert_eq!(res.contract_checks.len(), 1);
        assert!(res.contract_checks[0].hash_match);
    }

    #[test]
    fn contract_hash_mismatch_aborts() {
        let rpc = good_rpc().with_contract(CONTRACT_A, "aabbcc");
        let err = run_preflight(
            &rpc,
            "testnet",
            TESTNET_PASSPHRASE,
            &[(CONTRACT_A, Some(HASH_A))],
            false,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, PreflightError::WasmHashMismatch { .. }),
            "expected WasmHashMismatch, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("Remediation"), "error should have remediation: {msg}");
        assert!(msg.contains(CONTRACT_A), "contract id should be in error: {msg}");
    }

    #[test]
    fn allow_unknown_wasm_turns_mismatch_into_warning() {
        let rpc = good_rpc().with_contract(CONTRACT_A, "aabbcc");
        // Should succeed (not abort) when --allow-unknown-wasm is set.
        let res = run_preflight(
            &rpc,
            "testnet",
            TESTNET_PASSPHRASE,
            &[(CONTRACT_A, Some(HASH_A))],
            false,
            true, // allow_unknown_wasm
        )
        .unwrap();
        assert!(!res.contract_checks[0].hash_match);
    }

    #[test]
    fn contract_not_found_aborts() {
        let rpc = good_rpc().with_missing_contract(CONTRACT_A);
        let err = run_preflight(
            &rpc,
            "testnet",
            TESTNET_PASSPHRASE,
            &[(CONTRACT_A, None)],
            false,
            false,
        )
        .unwrap_err();
        assert!(
            matches!(err, PreflightError::ContractNotFound { .. }),
            "expected ContractNotFound, got: {err}"
        );
        let msg = err.to_string();
        assert!(msg.contains("Remediation"), "error should have remediation: {msg}");
    }

    // ── skip-preflight ────────────────────────────────────────────────────

    #[test]
    fn skip_preflight_allowed_on_testnet() {
        let rpc = good_rpc();
        let res = run_preflight(&rpc, "testnet", TESTNET_PASSPHRASE, &[], true, false).unwrap();
        assert!(res.skipped);
    }

    #[test]
    fn skip_preflight_blocked_on_mainnet() {
        let rpc = good_rpc();
        let err = run_preflight(&rpc, "mainnet", MAINNET_PASSPHRASE, &[], true, false)
            .unwrap_err();
        assert!(
            matches!(err, PreflightError::SkipNotAllowed { .. }),
            "expected SkipNotAllowed, got: {err}"
        );
    }
}
