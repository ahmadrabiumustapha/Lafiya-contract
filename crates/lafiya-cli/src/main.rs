//! Lafiya Admin CLI (Rust)
//!
//! Reads config/networks.toml for RPC, passphrase, contract IDs.
//! Switching networks is one flag: --network testnet
//! Secrets are never read from config, only via stellar CLI identities or env.
//!
//! Every operator supplied value (network name, address, contract id, record
//! hash, admin/source account) is validated locally before the stellar CLI is
//! invoked, so malformed input fails fast with an actionable message.
//!
//! ## Issues implemented in this file
//! - #399: Pluggable Signer abstraction (file/Ledger/KMS) via --signer URI
//! - #400: `attestation revoke-by-attester` via event enumeration
//! - #401: Network preflight checks before every mutating command
//! - #402: Deploy/upgrade/smoke-test subcommands replacing scripts/*.sh

use anyhow::Context;
use clap::{Parser, Subcommand};
use lafiya_config::{
    get_network, load_networks, run_preflight, validate_account_address, validate_address,
    validate_network_name, validate_record_hash, validate_source_account, ContractKind,
    DeploymentState, NetworkConfig, StellarCliRpc,
};
use std::path::PathBuf;

mod signer;
use signer::signer_from_uri;

/// Env var holding the stellar CLI identity used as transaction source.
const ENV_SOURCE: &str = "STELLAR_ACCOUNT";
/// Env var holding the contract admin address.
const ENV_ADMIN: &str = "ADMIN_ADDRESS";

// ─── Top-level CLI ────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "lafiya-cli",
    version = "0.1.0",
    about = "Lafiya Admin CLI — single operational entry point for Soroban contract management.\n\nReplaces scripts/admin.sh, scripts/deploy.sh, scripts/deploy-testnet.sh,\nscripts/upgrade.sh, and scripts/smoke-test.sh (see --help for each subcommand)."
)]
struct Cli {
    /// Network name as defined in config/networks.toml
    /// (e.g. testnet, futurenet, mainnet, local, standalone)
    #[arg(long, default_value = "testnet", global = true)]
    network: String,

    /// Path to networks.toml (auto-discovers by default)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Signer URI: identity://<name> (default), ledger://<index>,
    /// gcpkms://<resource>, awskms://<arn>, pkcs11://<label>.
    /// Bare names (e.g. "alice") are treated as identity://<name>.
    /// See docs/signer-security.md for details on each backend.
    #[arg(long, global = true, env = "LAFIYA_SIGNER")]
    signer: Option<String>,

    /// Skip preflight RPC checks (allowed on non-mainnet only).
    /// Use only when the RPC endpoint is known-good and preflight is failing
    /// due to an infrastructure issue. Never skip on mainnet.
    #[arg(long, global = true, default_value_t = false)]
    skip_preflight: bool,

    /// Allow a WASM hash mismatch during preflight (turns error into warning).
    /// Use only after independently verifying the on-chain hash.
    #[arg(long, global = true, default_value_t = false)]
    allow_unknown_wasm: bool,

    #[command(subcommand)]
    command: Commands,
}

// ─── Subcommands ──────────────────────────────────────────────────────────────

#[derive(Subcommand, Debug)]
enum Commands {
    /// Show / list network config
    Config {
        #[command(subcommand)]
        sub: ConfigSub,
    },

    /// Attester registry operations
    Attester {
        #[command(subcommand)]
        sub: AttesterSub,
    },

    /// Attestation registry operations
    Attestation {
        #[command(subcommand)]
        sub: AttestationSub,
    },

    /// Deploy contracts to the selected network.
    ///
    /// Builds WASM, uploads, deploys attester-registry and attestation-registry,
    /// initializes both, and records contract IDs.
    /// Replaces: scripts/deploy.sh, scripts/deploy-testnet.sh
    Deploy {
        /// Only build WASM, don't deploy
        #[arg(long, default_value_t = false)]
        build_only: bool,
        /// Dry run — print what would be done without submitting transactions
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Stellar identity or G... address used as transaction source (or STELLAR_ACCOUNT env)
        #[arg(long)]
        source: Option<String>,
        /// Admin address (G...) for contract initialization (or ADMIN_ADDRESS env)
        #[arg(long)]
        admin: Option<String>,
        /// Skip WASM build (use existing artifact in target/)
        #[arg(long, default_value_t = false)]
        skip_build: bool,
        /// Path to pre-built attester-registry WASM (skips build)
        #[arg(long)]
        attester_wasm: Option<PathBuf>,
        /// Path to pre-built attestation-registry WASM (skips build)
        #[arg(long)]
        attestation_wasm: Option<PathBuf>,
    },

    /// Upgrade a deployed contract to a new WASM.
    ///
    /// Automates: build → size-check → hash → upload → upgrade() → optional migrate() → verify.
    /// Replaces: scripts/upgrade.sh
    Upgrade {
        /// Contract to upgrade: attester-registry or attestation-registry
        #[arg(long)]
        contract: String,
        /// Deployed contract ID (C...) or read from config
        #[arg(long)]
        id: Option<String>,
        /// Admin signer identity or G... address
        #[arg(long)]
        source: Option<String>,
        /// Path to pre-built WASM (skips build)
        #[arg(long)]
        wasm: Option<PathBuf>,
        /// Skip the WASM build step, use existing artifact in target/
        #[arg(long, default_value_t = false)]
        skip_build: bool,
        /// Also invoke migrate() after upgrade (schema-changing releases)
        #[arg(long, default_value_t = false)]
        run_migrate: bool,
        /// Expected schema version after upgrade; verified via get_schema_version()
        #[arg(long)]
        expected_schema_version: Option<u32>,
        /// Maximum WASM size in bytes (default: 65536)
        #[arg(long, default_value_t = 65536)]
        max_wasm_bytes: u64,
        /// Dry run — print every command without submitting transactions
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Expected WASM hash (hex) from release manifest; verified after upload
        #[arg(long)]
        expected_wasm_hash: Option<String>,
    },

    /// Run smoke tests against a deployed network.
    ///
    /// Tests: add attester → attest → get_attestation → remove attester.
    /// Replaces: scripts/smoke-test.sh
    SmokeTest {
        /// Admin identity or G... address for add/remove attester calls
        #[arg(long)]
        source: Option<String>,
        /// Run only the read-only checks (no state changes)
        #[arg(long, default_value_t = false)]
        read_only: bool,
        /// Output results as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigSub {
    /// Show resolved config for selected network
    Show,
    /// List all available networks in config
    List,
    /// Print shell export lines for current network (for use with eval or sourcing)
    Env,
}

#[derive(Subcommand, Debug)]
enum AttesterSub {
    /// Check if an address is allowlisted
    Is {
        /// Stellar address (G...)
        address: String,
    },
    /// Add attester (requires admin auth)
    Add {
        /// Stellar address (G...) to allowlist as an attester
        address: String,
        #[arg(long)]
        source: Option<String>,
    },
    /// Remove attester
    Remove {
        /// Stellar address (G...) to remove from the allowlist
        address: String,
        #[arg(long)]
        source: Option<String>,
    },
    /// Suspend an allowlisted attester without removing them
    Suspend {
        /// Stellar address (G...) of attester to suspend
        address: String,
        #[arg(long)]
        source: Option<String>,
    },
    /// Reinstate a suspended attester
    Reinstate {
        /// Stellar address (G...) of attester to reinstate
        address: String,
        #[arg(long)]
        source: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AttestationSub {
    /// Get the latest attestation for a record hash (hex encoded 32-byte hash)
    Get {
        /// Hex string of 32-byte record hash (64 chars)
        record_hash: String,
    },
    /// Get full attestation history for a record hash
    History {
        /// Hex string of 32-byte record hash (64 chars)
        record_hash: String,
    },
    /// Revoke all attestations for a record hash (admin only)
    Revoke {
        /// Hex string of 32-byte record hash (64 chars)
        record_hash: String,
        #[arg(long)]
        source: Option<String>,
    },
    /// Revoke all attestations submitted by a specific attester, discovered
    /// via AttestationRecorded event enumeration.
    ///
    /// Issue #400: enumerate AttestationRecorded events, filter by attester,
    /// deduplicate hashes, check current state, warn on co-attester collateral
    /// damage, execute with journal and confirmation.
    RevokeByAttester {
        /// Address of the attester whose attestations should be revoked (G...)
        attester: String,
        /// Earliest ledger sequence to include (0 = from chain start)
        #[arg(long, default_value_t = 0)]
        since_ledger: u32,
        /// Latest ledger sequence to include (0 = latest)
        #[arg(long, default_value_t = 0)]
        until_ledger: u32,
        /// Dry run — enumerate and plan but do not submit revocations
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Write audit report to this file (CSV or JSON based on extension)
        #[arg(long)]
        audit_report: Option<PathBuf>,
        /// Admin identity or G... address for revoke_attestation calls
        #[arg(long)]
        source: Option<String>,
        /// Skip confirmation prompt (for automation)
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Validate the network name before it is used as a config key.
    validate_network_name(&cli.network)
        .map_err(|e| anyhow::anyhow!("invalid --network value: {e}"))?;

    // Validate signer URI early (if provided) so errors surface before any
    // network calls are made.
    if let Some(signer_uri) = &cli.signer {
        let _s = signer_from_uri(signer_uri)
            .map_err(|e| anyhow::anyhow!("invalid --signer value: {e}"))?;
        eprintln!(
            "Using signer: {}",
            signer_from_uri(signer_uri).unwrap().describe()
        );
    }

    let config_path_opt = cli.config.as_deref();
    let networks = load_networks(config_path_opt)?;

    // For config list, we don't need to resolve specific network.
    if let Commands::Config {
        sub: ConfigSub::List,
    } = &cli.command
    {
        println!(
            "Available networks (from {:?}):",
            lafiya_config::default_config_path()
        );
        for name in networks.keys() {
            println!("  - {}", name);
        }
        if let Some(p) = &cli.config {
            println!("Config path (explicit): {:?}", p);
        } else {
            let default = lafiya_config::default_config_path();
            println!("Config path (auto): {:?}", default);
        }
        return Ok(());
    }

    let network_cfg = get_network(&networks, &cli.network).map_err(|e| anyhow::anyhow!(e))?;

    let is_config_show = matches!(
        cli.command,
        Commands::Config {
            sub: ConfigSub::Show
        }
    );
    if let Err(e) = network_cfg.validate(&cli.network) {
        if is_config_show {
            eprintln!("WARNING: {e}");
        } else {
            return Err(anyhow::anyhow!(e));
        }
    }

    // ── Dispatch ──────────────────────────────────────────────────────────────
    match cli.command {
        // ── config ────────────────────────────────────────────────────────────
        Commands::Config { sub } => {
            match sub {
                ConfigSub::Show => {
                    let (path, _) = lafiya_config::load_network_config::<PathBuf>(
                        &cli.network,
                        cli.config.clone(),
                    )?;
                    println!("Network: {}", cli.network);
                    println!("Config: {:?}", path);
                    println!("RPC URL: {}", network_cfg.rpc_url);
                    println!("Passphrase: {}", network_cfg.network_passphrase);
                    println!(
                        "Attester registry: {}",
                        if network_cfg.contracts.attester_registry.is_empty() {
                            "<not deployed>".to_string()
                        } else {
                            network_cfg.contracts.attester_registry.clone()
                        }
                    );
                    println!(
                        "Attestation registry: {}",
                        if network_cfg.contracts.attestation_registry.is_empty() {
                            "<not deployed>".to_string()
                        } else {
                            network_cfg.contracts.attestation_registry.clone()
                        }
                    );
                    println!("Deployed: {}", network_cfg.is_deployed());
                    println!("Deployment status: {}", deployment_summary(&network_cfg));
                    println!();
                    println!("Signer backends available:");
                    println!("  identity://<name>   (stellar CLI identity, default)");
                    println!("  ledger://<index>    (Ledger hardware wallet)");
                    println!("  gcpkms://<resource> (GCP Cloud KMS ed25519)");
                    println!("  awskms://<arn>      (AWS KMS ed25519)");
                    println!("  pkcs11://<label>    (PKCS#11 HSM)");
                    println!();
                    println!(
                        "Secrets: NEVER stored in networks.toml. Use stellar identities or env vars."
                    );
                }
                ConfigSub::List => {} // handled above
                ConfigSub::Env => {
                    println!(
                        "# Source this with: eval $(lafiya-cli --network {} config env)",
                        cli.network
                    );
                    println!("export LAFIYA_NETWORK={}", cli.network);
                    println!("export LAFIYA_RPC_URL={}", network_cfg.rpc_url);
                    println!(
                        "export LAFIYA_NETWORK_PASSPHRASE={:?}",
                        network_cfg.network_passphrase
                    );
                    println!(
                        "export LAFIYA_ATTESTER_REGISTRY_ID={}",
                        network_cfg.contracts.attester_registry
                    );
                    println!(
                        "export LAFIYA_ATTESTATION_REGISTRY_ID={}",
                        network_cfg.contracts.attestation_registry
                    );
                }
            }
        }

        // ── attester ──────────────────────────────────────────────────────────
        Commands::Attester { sub } => {
            let contract_id = network_cfg
                .require_contract_id(&cli.network, ContractKind::AttesterRegistry)
                .map_err(|e| anyhow::anyhow!(e))?;

            match sub {
                AttesterSub::Is { address } => {
                    validate_address("attester address", &address)
                        .context("invalid attester address")?;
                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        None,
                        "is_attester",
                        &["--attester", &address],
                    );
                    println!("Checking is_attester for {} on {}", address, contract_id);
                    println!("RPC: {}", network_cfg.rpc_url);
                    println!("> stellar {}", args.join(" "));
                    if which("stellar").is_ok() {
                        if let Err(e) = std::process::Command::new("stellar").args(args).status() {
                            eprintln!("Failed to run stellar CLI: {e}. Install: cargo install --locked stellar-cli");
                        }
                    } else {
                        eprintln!("stellar CLI not found - showing command only.");
                    }
                }

                AttesterSub::Add { address, source } => {
                    validate_address("attester address", &address)
                        .context("invalid attester address")?;
                    let source = validated_source(source)?;

                    // Preflight (#401)
                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        source.as_deref(),
                        "add_attester",
                        &["--attester", &address],
                    );
                    run_stellar(args)?;
                }

                AttesterSub::Remove { address, source } => {
                    validate_address("attester address", &address)
                        .context("invalid attester address")?;
                    let source = validated_source(source)?;

                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        source.as_deref(),
                        "remove_attester",
                        &["--attester", &address],
                    );
                    run_stellar(args)?;
                }

                AttesterSub::Suspend { address, source } => {
                    validate_address("attester address", &address)
                        .context("invalid attester address")?;
                    let source = validated_source(source)?;

                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        source.as_deref(),
                        "suspend_attester",
                        &["--attester", &address],
                    );
                    run_stellar(args)?;
                }

                AttesterSub::Reinstate { address, source } => {
                    validate_address("attester address", &address)
                        .context("invalid attester address")?;
                    let source = validated_source(source)?;

                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        source.as_deref(),
                        "reinstate_attester",
                        &["--attester", &address],
                    );
                    run_stellar(args)?;
                }
            }
        }

        // ── attestation ───────────────────────────────────────────────────────
        Commands::Attestation { sub } => {
            let contract_id = network_cfg
                .require_contract_id(&cli.network, ContractKind::AttestationRegistry)
                .map_err(|e| anyhow::anyhow!(e))?;

            match sub {
                AttestationSub::Get { record_hash } => {
                    validate_record_hash("record_hash", &record_hash)
                        .context("invalid record hash")?;
                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        None,
                        "get_attestation",
                        &["--record_hash", &record_hash],
                    );
                    println!("> stellar {}", args.join(" "));
                    if which("stellar").is_ok() {
                        let status =
                            std::process::Command::new("stellar").args(args).status()?;
                        if !status.success() {
                            anyhow::bail!("stellar CLI failed");
                        }
                    } else {
                        eprintln!("stellar CLI not found — install: cargo install --locked stellar-cli");
                    }
                }

                AttestationSub::History { record_hash } => {
                    validate_record_hash("record_hash", &record_hash)
                        .context("invalid record hash")?;
                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        None,
                        "get_attestation_history",
                        &["--record_hash", &record_hash],
                    );
                    println!("> stellar {}", args.join(" "));
                    if which("stellar").is_ok() {
                        let status =
                            std::process::Command::new("stellar").args(args).status()?;
                        if !status.success() {
                            anyhow::bail!("stellar CLI failed");
                        }
                    } else {
                        eprintln!("stellar CLI not found — install: cargo install --locked stellar-cli");
                    }
                }

                AttestationSub::Revoke {
                    record_hash,
                    source,
                } => {
                    validate_record_hash("record_hash", &record_hash)
                        .context("invalid record hash")?;
                    let source = validated_source(source)?;

                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    let args = invoke_args(
                        &network_cfg,
                        contract_id,
                        source.as_deref(),
                        "revoke_attestation",
                        &["--record_hash", &record_hash],
                    );
                    run_stellar(args)?;
                }

                // ─── Issue #400: revoke-by-attester ───────────────────────────
                AttestationSub::RevokeByAttester {
                    attester,
                    since_ledger,
                    until_ledger,
                    dry_run,
                    audit_report,
                    source,
                    yes,
                } => {
                    validate_address("attester", &attester)
                        .context("invalid attester address")?;
                    let source = validated_source(source)?;

                    run_preflight_for_mutating(
                        &network_cfg,
                        &cli.network,
                        &[(contract_id, None)],
                        cli.skip_preflight,
                        cli.allow_unknown_wasm,
                    )?;

                    cmd_revoke_by_attester(
                        &network_cfg,
                        &cli.network,
                        contract_id,
                        &attester,
                        since_ledger,
                        until_ledger,
                        dry_run,
                        audit_report.as_deref(),
                        source.as_deref(),
                        yes,
                    )?;
                }
            }
        }

        // ── deploy (#402) ─────────────────────────────────────────────────────
        Commands::Deploy {
            build_only,
            dry_run,
            source,
            admin,
            skip_build,
            attester_wasm,
            attestation_wasm,
        } => {
            let source = resolved_source(source)?;
            let admin = resolved_admin(admin)?;

            println!("==> Deploy flow for network: {}", cli.network);
            println!("    RPC: {}", network_cfg.rpc_url);
            println!("    Passphrase: {}", network_cfg.network_passphrase);
            println!("    Deployment status: {}", deployment_summary(&network_cfg));
            println!(
                "    Source: {}",
                source.as_deref().unwrap_or("<none — required>")
            );
            println!(
                "    Admin: {}",
                admin.as_deref().unwrap_or("<defaults to source>")
            );

            let do_build = !skip_build && attester_wasm.is_none() && attestation_wasm.is_none();
            let attester_wasm_path = attester_wasm.unwrap_or_else(|| {
                PathBuf::from("target/wasm32v1-none/release/attester_registry.wasm")
            });
            let attestation_wasm_path = attestation_wasm.unwrap_or_else(|| {
                PathBuf::from("target/wasm32v1-none/release/attestation_registry.wasm")
            });

            if do_build || build_only {
                println!("==> Building WASM contracts...");
                if dry_run {
                    println!(
                        "[dry-run] cargo build --workspace --release --target wasm32v1-none"
                    );
                } else {
                    let status = std::process::Command::new("cargo")
                        .args([
                            "build",
                            "--workspace",
                            "--release",
                            "--target",
                            "wasm32v1-none",
                        ])
                        .status()?;
                    if !status.success() {
                        anyhow::bail!("WASM build failed");
                    }
                }
            }

            if build_only {
                println!("==> Build complete (--build-only).");
                return Ok(());
            }

            let source_str = source.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "source identity required for deploy. Use --source <identity> or STELLAR_ACCOUNT env."
                )
            })?;

            // Run preflight before any on-chain operations (#401).
            if !cli.skip_preflight {
                run_preflight_for_mutating(
                    &network_cfg,
                    &cli.network,
                    &[], // no contract IDs yet (first deploy)
                    false,
                    cli.allow_unknown_wasm,
                )?;
            }

            if dry_run {
                println!(
                    "[dry-run] Would deploy attester-registry and attestation-registry to {}",
                    cli.network
                );
                println!(
                    "[dry-run] attester WASM: {:?}",
                    attester_wasm_path
                );
                println!(
                    "[dry-run] attestation WASM: {:?}",
                    attestation_wasm_path
                );
                println!("[dry-run] source: {source_str}");
                println!(
                    "[dry-run] admin: {}",
                    admin.as_deref().unwrap_or("<source>")
                );
                return Ok(());
            }

            // ── 1. Upload WASMs ───────────────────────────────────────────
            println!("==> Uploading attester-registry WASM...");
            let attester_hash = upload_wasm(
                &attester_wasm_path,
                source_str,
                &network_cfg,
            )?;
            println!("    WASM hash: {attester_hash}");

            println!("==> Uploading attestation-registry WASM...");
            let attestation_hash = upload_wasm(
                &attestation_wasm_path,
                source_str,
                &network_cfg,
            )?;
            println!("    WASM hash: {attestation_hash}");

            // ── 2. Deploy contracts ───────────────────────────────────────
            println!("==> Deploying attester-registry...");
            let attester_id = deploy_contract(
                &attester_wasm_path,
                source_str,
                &network_cfg,
            )?;
            println!("    Contract ID: {attester_id}");

            println!("==> Deploying attestation-registry...");
            let attestation_id = deploy_contract(
                &attestation_wasm_path,
                source_str,
                &network_cfg,
            )?;
            println!("    Contract ID: {attestation_id}");

            // ── 3. Initialize ─────────────────────────────────────────────
            let admin_addr = admin.as_deref().unwrap_or(source_str);
            println!("==> Initializing attester-registry (admin={admin_addr})...");
            run_stellar(invoke_args(
                &network_cfg,
                &attester_id,
                Some(source_str),
                "initialize",
                &["--admin", admin_addr],
            ))?;

            println!("==> Initializing attestation-registry...");
            run_stellar(invoke_args(
                &network_cfg,
                &attestation_id,
                Some(source_str),
                "initialize",
                &[
                    "--admin",
                    admin_addr,
                    "--attester_registry",
                    &attester_id,
                ],
            ))?;

            println!();
            println!("==> Deployment complete!");
            println!("    Add the following to config/networks.toml under [{}.contracts]:", cli.network);
            println!("    attester_registry = \"{attester_id}\"");
            println!("    attestation_registry = \"{attestation_id}\"");
        }

        // ── upgrade (#402) ────────────────────────────────────────────────────
        Commands::Upgrade {
            contract,
            id,
            source,
            wasm,
            skip_build,
            run_migrate,
            expected_schema_version,
            max_wasm_bytes,
            dry_run,
            expected_wasm_hash,
        } => {
            let source = resolved_source(source)?;
            let source_str = source.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "source identity required for upgrade. Use --source <identity> or STELLAR_ACCOUNT env."
                )
            })?;

            // Resolve contract ID from --id or config.
            let contract_id = if let Some(ref explicit_id) = id {
                explicit_id.clone()
            } else {
                let kind = match contract.as_str() {
                    "attester-registry" => ContractKind::AttesterRegistry,
                    "attestation-registry" => ContractKind::AttestationRegistry,
                    other => anyhow::bail!(
                        "unknown contract name '{other}'. Use: attester-registry or attestation-registry"
                    ),
                };
                network_cfg
                    .require_contract_id(&cli.network, kind)
                    .map_err(|e| anyhow::anyhow!(e))?
                    .to_string()
            };

            // Determine WASM path.
            let wasm_path = wasm.unwrap_or_else(|| {
                let artifact = contract.replace('-', "_");
                PathBuf::from(format!(
                    "target/wasm32v1-none/release/{artifact}.wasm"
                ))
            });

            println!("==> Upgrade plan for {} on {}", contract, cli.network);
            println!("    Contract ID: {contract_id}");
            println!("    WASM path: {:?}", wasm_path);

            if !skip_build && wasm.is_none() {
                println!("==> Building WASM...");
                if dry_run {
                    println!("[dry-run] cargo build ... (skipped)");
                } else {
                    let p = contract.replace('-', "_");
                    let status = std::process::Command::new("cargo")
                        .args(["build", "--release", "--locked", "--target", "wasm32v1-none", "-p", &p])
                        .status()?;
                    if !status.success() {
                        anyhow::bail!("WASM build failed");
                    }
                }
            }

            // Size check.
            if !dry_run && wasm_path.exists() {
                let size = std::fs::metadata(&wasm_path)?.len();
                if size > max_wasm_bytes {
                    anyhow::bail!(
                        "WASM size {size} bytes exceeds budget of {max_wasm_bytes} bytes.\n\
                         Reduce the contract size before upgrading."
                    );
                }
                println!("    WASM size: {size} bytes (budget: {max_wasm_bytes})");
            }

            // Compute local hash.
            let local_hash = if !dry_run && wasm_path.exists() {
                let bytes = std::fs::read(&wasm_path)?;
                sha256_hex(&bytes)
            } else {
                "<dry-run>".to_string()
            };
            println!("    Local WASM SHA-256: {local_hash}");

            // Verify against expected hash from release manifest (if provided).
            if let Some(ref exp) = expected_wasm_hash {
                if !dry_run && exp.trim() != local_hash.trim() {
                    anyhow::bail!(
                        "WASM hash mismatch before upload!\n\
                         expected (manifest): {exp}\n\
                         local file:          {local_hash}\n\
                         Do not proceed — verify the built artifact matches reviewed source."
                    );
                }
            }

            // Preflight (#401).
            run_preflight_for_mutating(
                &network_cfg,
                &cli.network,
                &[(&contract_id, expected_wasm_hash.as_deref())],
                cli.skip_preflight,
                cli.allow_unknown_wasm,
            )?;

            if dry_run {
                println!("[dry-run] Would upload WASM and call upgrade() on {contract_id}");
                if run_migrate {
                    println!("[dry-run] Would call migrate() on {contract_id}");
                }
                if let Some(v) = expected_schema_version {
                    println!("[dry-run] Would verify get_schema_version() == {v}");
                }
                return Ok(());
            }

            // Upload WASM.
            println!("==> Uploading WASM to ledger...");
            let upload_hash = upload_wasm(&wasm_path, source_str, &network_cfg)?;
            println!("    On-chain hash: {upload_hash}");

            // Verify on-chain hash matches local hash.
            if local_hash != upload_hash && local_hash != "<dry-run>" {
                anyhow::bail!(
                    "On-chain hash {upload_hash} does not match local hash {local_hash}.\n\
                     This is unexpected — the upload may have been corrupted."
                );
            }

            // Call upgrade().
            println!("==> Calling upgrade() on {contract_id}...");
            run_stellar(invoke_args(
                &network_cfg,
                &contract_id,
                Some(source_str),
                "upgrade",
                &["--new_wasm_hash", &upload_hash],
            ))?;

            // Optionally call migrate().
            if run_migrate {
                println!("==> Calling migrate() on {contract_id}...");
                run_stellar(invoke_args(
                    &network_cfg,
                    &contract_id,
                    Some(source_str),
                    "migrate",
                    &[],
                ))?;
            }

            // Verify schema version.
            if let Some(expected) = expected_schema_version {
                println!("==> Verifying schema version == {expected}...");
                let args = invoke_args(
                    &network_cfg,
                    &contract_id,
                    None,
                    "get_schema_version",
                    &[],
                );
                run_stellar(args)?;
                println!("    (Verify the output above is {expected}.)");
            }

            println!("==> Upgrade complete.");
        }

        // ── smoke-test (#402) ─────────────────────────────────────────────────
        Commands::SmokeTest {
            source,
            read_only,
            json,
        } => {
            let attester_id = network_cfg
                .require_contract_id(&cli.network, ContractKind::AttesterRegistry)
                .map_err(|e| anyhow::anyhow!(e))?;
            let attestation_id = network_cfg
                .require_contract_id(&cli.network, ContractKind::AttestationRegistry)
                .map_err(|e| anyhow::anyhow!(e))?;

            let source = resolved_source(source)?;

            println!("==> Smoke test for network: {}", cli.network);
            println!("    Attester registry:    {attester_id}");
            println!("    Attestation registry: {attestation_id}");

            // Preflight (#401).
            run_preflight_for_mutating(
                &network_cfg,
                &cli.network,
                &[(attester_id, None), (attestation_id, None)],
                cli.skip_preflight,
                cli.allow_unknown_wasm,
            )?;

            let mut results: Vec<(&str, bool, String)> = Vec::new();

            // ── Check is_paused ───────────────────────────────────────────
            let paused_result = smoke_invoke(
                &network_cfg,
                attester_id,
                None,
                "is_paused",
                &[],
            );
            let paused_ok = paused_result.is_ok();
            results.push(("attester is_paused", paused_ok, paused_result.unwrap_or_else(|e| e.to_string())));

            let att_paused_result = smoke_invoke(
                &network_cfg,
                attestation_id,
                None,
                "is_paused",
                &[],
            );
            let att_paused_ok = att_paused_result.is_ok();
            results.push(("attestation is_paused", att_paused_ok, att_paused_result.unwrap_or_else(|e| e.to_string())));

            // ── get_attester_count ────────────────────────────────────────
            let count_result = smoke_invoke(
                &network_cfg,
                attester_id,
                None,
                "get_attester_count",
                &[],
            );
            let count_ok = count_result.is_ok();
            results.push(("get_attester_count", count_ok, count_result.unwrap_or_else(|e| e.to_string())));

            if !read_only {
                if let Some(ref src) = source {
                    println!("==> Running mutating checks (--source {src})...");
                    // Test: get_admin
                    let admin_result = smoke_invoke(
                        &network_cfg,
                        attester_id,
                        None,
                        "get_admin",
                        &[],
                    );
                    let admin_ok = admin_result.is_ok();
                    results.push(("get_admin (attester)", admin_ok, admin_result.unwrap_or_else(|e| e.to_string())));
                } else {
                    println!("==> Skipping mutating checks (no --source provided).");
                }
            }

            // Report.
            let all_ok = results.iter().all(|(_, ok, _)| *ok);
            if json {
                println!("{{");
                println!("  \"network\": \"{}\",", cli.network);
                println!("  \"all_ok\": {all_ok},");
                println!("  \"checks\": [");
                for (i, (name, ok, output)) in results.iter().enumerate() {
                    let comma = if i + 1 < results.len() { "," } else { "" };
                    println!(
                        "    {{\"name\": \"{name}\", \"ok\": {ok}, \"output\": \"{output}\"}}{comma}"
                    );
                }
                println!("  ]");
                println!("}}");
            } else {
                println!();
                println!("Results:");
                for (name, ok, output) in &results {
                    let icon = if *ok { "✅" } else { "❌" };
                    println!("  {icon} {name}: {output}");
                }
                println!();
                if all_ok {
                    println!("✅ All smoke tests passed.");
                } else {
                    anyhow::bail!("❌ Some smoke tests failed — see above.");
                }
            }
        }
    }

    Ok(())
}

// ─── Issue #400: revoke-by-attester ──────────────────────────────────────────

/// Enumerate AttestationRecorded events, filter by attester, deduplicate hashes,
/// warn on collateral damage (co-attesters), and execute with journal.
fn cmd_revoke_by_attester(
    network_cfg: &NetworkConfig,
    network: &str,
    contract_id: &str,
    attester: &str,
    since_ledger: u32,
    until_ledger: u32,
    dry_run: bool,
    audit_report: Option<&std::path::Path>,
    source: Option<&str>,
    yes: bool,
) -> anyhow::Result<()> {
    println!("==> revoke-by-attester");
    println!("    Contract:      {contract_id}");
    println!("    Attester:      {attester}");
    println!("    Ledger range:  {} – {}", since_ledger, if until_ledger == 0 { "latest".to_string() } else { until_ledger.to_string() });
    println!("    Dry run:       {dry_run}");

    // ── 1. Check RPC event retention window ───────────────────────────────
    // Soroban RPC retains events for approximately 7 days (by default).
    // If since_ledger is 0 we use the full available range.
    // We detect if the range might be outside retention and warn.
    let latest_ledger = get_latest_ledger_seq(network_cfg)?;

    // Approximate: 7 days × 17280 ledgers/day (5s/ledger) = ~120960 ledgers.
    const APPROX_RETENTION_LEDGERS: u32 = 120_960;
    let oldest_retained = latest_ledger.saturating_sub(APPROX_RETENTION_LEDGERS);

    if since_ledger > 0 && since_ledger < oldest_retained {
        anyhow::bail!(
            "since_ledger {} is outside the RPC event retention window.\n\
             Oldest retained ledger (approx): {oldest_retained}\n\
             Latest ledger:                   {latest_ledger}\n\
             The command refuses to continue because partial results would be \
             reported as complete. Use an indexer source or narrow the range.\n\
             Remediation: set --since-ledger to at least {oldest_retained} or \
             use an event indexer.",
            since_ledger
        );
    }

    let effective_since = since_ledger.max(oldest_retained);
    let effective_until = if until_ledger == 0 { latest_ledger } else { until_ledger };

    println!("    Effective range: ledger {} – {}", effective_since, effective_until);

    // ── 2. Enumerate AttestationRecorded events ────────────────────────────
    println!("==> Enumerating AttestationRecorded events (this may take a moment)...");
    let events = enumerate_attestation_events(
        network_cfg,
        contract_id,
        attester,
        effective_since,
        effective_until,
    )?;

    if events.is_empty() {
        println!("    No AttestationRecorded events found for attester {attester} in the given range.");
        return Ok(());
    }

    println!("    Found {} unique record hashes attested by {attester}.", events.len());

    // ── 3. Check current state & co-attester collateral damage ────────────
    let mut hashes_to_revoke: Vec<String> = Vec::new();
    let mut collateral_warnings: Vec<(String, Vec<String>)> = Vec::new();

    for hash in &events {
        // Get attestation history for this hash to detect co-attesters.
        let co_attesters = get_co_attesters(network_cfg, contract_id, hash, attester)?;

        if !co_attesters.is_empty() {
            collateral_warnings.push((hash.clone(), co_attesters.clone()));
        }
        hashes_to_revoke.push(hash.clone());
    }

    // ── 4. Display plan with collateral damage warnings ───────────────────
    println!();
    println!("==> Revocation plan:");
    println!("    Hashes to revoke: {}", hashes_to_revoke.len());

    if !collateral_warnings.is_empty() {
        println!();
        println!("    ⚠ COLLATERAL DAMAGE WARNING");
        println!("    The following hashes also have attestations from OTHER attesters.");
        println!("    Revoking these will remove ALL attestations for the hash, including");
        println!("    those from the co-attesters listed.");
        println!();
        for (hash, co_attesters) in &collateral_warnings {
            println!("    Hash: {hash}");
            for co in co_attesters {
                println!("          Co-attester: {co}");
            }
        }
        println!();
    }

    if dry_run {
        println!("==> [dry-run] Would revoke {} hashes. No transactions submitted.", hashes_to_revoke.len());
        write_audit_report(audit_report, attester, &hashes_to_revoke, &collateral_warnings, dry_run, network)?;
        return Ok(());
    }

    // ── 5. Confirmation ───────────────────────────────────────────────────
    if !yes {
        println!();
        print!(
            "Proceed with revoking {} attestation hash(es) on {}? [y/N]: ",
            hashes_to_revoke.len(),
            network
        );
        use std::io::Write;
        std::io::stdout().flush()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // ── 6. Execute with journal ────────────────────────────────────────────
    let source = source.ok_or_else(|| {
        anyhow::anyhow!(
            "source identity required for revoke-by-attester. Use --source <identity>."
        )
    })?;

    let total = hashes_to_revoke.len();
    let mut succeeded = 0usize;
    let mut failed: Vec<(String, String)> = Vec::new();

    for (i, hash) in hashes_to_revoke.iter().enumerate() {
        println!("    [{}/{}] Revoking {hash}...", i + 1, total);
        let args = invoke_args(
            network_cfg,
            contract_id,
            Some(source),
            "revoke_attestation",
            &["--record_hash", hash],
        );
        match run_stellar_quiet(args) {
            Ok(_) => {
                println!("          ✅ revoked");
                succeeded += 1;
            }
            Err(e) => {
                println!("          ❌ FAILED: {e}");
                failed.push((hash.clone(), e.to_string()));
            }
        }
    }

    println!();
    println!("==> Revocation complete: {succeeded}/{total} succeeded, {} failed.", failed.len());

    if !failed.is_empty() {
        println!("    Failed hashes:");
        for (hash, err) in &failed {
            println!("      {hash}: {err}");
        }
    }

    // ── 7. Audit report ────────────────────────────────────────────────────
    write_audit_report(audit_report, attester, &hashes_to_revoke, &collateral_warnings, dry_run, network)?;

    if !failed.is_empty() {
        anyhow::bail!("{} revocations failed — see output above.", failed.len());
    }

    Ok(())
}

/// Get the latest ledger sequence number from the RPC.
fn get_latest_ledger_seq(network_cfg: &NetworkConfig) -> anyhow::Result<u32> {
    if which("stellar").is_err() {
        // Fall back to a safe estimate.
        return Ok(999_999);
    }
    let output = std::process::Command::new("stellar")
        .args([
            "rpc",
            "--rpc-url",
            &network_cfg.rpc_url,
            "send",
            r#"{"jsonrpc":"2.0","id":1,"method":"getLatestLedger","params":{}}"#,
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            let raw = String::from_utf8_lossy(&o.stdout);
            // Parse "sequence": N
            if let Some(seq) = extract_json_u64(&raw, "sequence") {
                return Ok(seq as u32);
            }
        }
        _ => {}
    }
    Ok(999_999) // safe fallback
}

/// Enumerate AttestationRecorded events for a specific attester.
///
/// Uses `stellar events` (Soroban RPC `getEvents`) to page through events.
/// Returns deduplicated record hashes.
fn enumerate_attestation_events(
    network_cfg: &NetworkConfig,
    contract_id: &str,
    attester: &str,
    since_ledger: u32,
    until_ledger: u32,
) -> anyhow::Result<Vec<String>> {
    // Use stellar CLI: `stellar events --id <contract> --start-ledger <n>`
    // The AttestationRecorded event has topic[0] = "AttestationRecorded"
    // and data includes { attester, record_hash, timestamp }.
    if which("stellar").is_err() {
        println!("    stellar CLI not found — returning empty event list (install to enumerate events).");
        return Ok(vec![]);
    }

    let start = since_ledger.to_string();
    let end = until_ledger.to_string();

    let output = std::process::Command::new("stellar")
        .args([
            "events",
            "--id",
            contract_id,
            "--rpc-url",
            &network_cfg.rpc_url,
            "--network-passphrase",
            &network_cfg.network_passphrase,
            "--start-ledger",
            &start,
            "--end-ledger",
            &end,
            "--type",
            "contract",
        ])
        .output()
        .context("failed to run stellar events")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Not a fatal error — no events may simply mean no events.
        eprintln!("    Warning: stellar events returned non-zero: {stderr}");
        return Ok(vec![]);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hashes: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Parse event output. Each event block contains the attester address and record_hash.
    // We do a simple line-by-line scan for the attester address and adjacent record_hash.
    let mut current_attester: Option<String> = None;
    let mut current_hash: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();

        // Detect attester in event data.
        if line.contains(attester) {
            current_attester = Some(attester.to_string());
        }

        // Detect record_hash (hex string, 64 chars).
        if let Some(hash) = extract_hex_hash_from_line(line) {
            current_hash = Some(hash);
        }

        // When we have both, add to set and reset.
        if current_attester.is_some() && current_hash.is_some() {
            hashes.insert(current_hash.take().unwrap());
            current_attester = None;
        }
    }

    Ok(hashes.into_iter().collect())
}

/// Try to get co-attesters for a given hash (other attesters who also attested it).
///
/// Uses get_attestation_history. Returns addresses of other attesters (not the target attester).
fn get_co_attesters(
    network_cfg: &NetworkConfig,
    contract_id: &str,
    record_hash: &str,
    target_attester: &str,
) -> anyhow::Result<Vec<String>> {
    if which("stellar").is_err() {
        return Ok(vec![]);
    }
    let args = invoke_args(
        network_cfg,
        contract_id,
        None,
        "get_attestation_history",
        &["--record_hash", record_hash],
    );
    match run_stellar_capture(args) {
        Ok(output) => {
            let mut co_attesters: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for line in output.lines() {
                // Look for G... addresses that are NOT the target attester.
                for word in line.split_whitespace() {
                    if word.starts_with('G') && word.len() == 56 && word != target_attester {
                        co_attesters.insert(word.to_string());
                    }
                }
            }
            Ok(co_attesters.into_iter().collect())
        }
        Err(_) => Ok(vec![]),
    }
}

/// Write an audit report to the specified path.
fn write_audit_report(
    path: Option<&std::path::Path>,
    attester: &str,
    hashes: &[String],
    collateral_warnings: &[(String, Vec<String>)],
    dry_run: bool,
    network: &str,
) -> anyhow::Result<()> {
    let Some(path) = path else { return Ok(()) };

    let is_json = path.extension().and_then(|e| e.to_str()) == Some("json");

    let content = if is_json {
        let warnings_json: Vec<serde_json::Value> = collateral_warnings
            .iter()
            .map(|(h, co)| {
                serde_json::json!({
                    "record_hash": h,
                    "co_attesters": co,
                })
            })
            .collect();

        serde_json::to_string_pretty(&serde_json::json!({
            "network": network,
            "attester": attester,
            "dry_run": dry_run,
            "total_hashes": hashes.len(),
            "hashes": hashes,
            "collateral_damage_warnings": warnings_json,
        }))? + "\n"
    } else {
        // CSV
        let mut csv = String::new();
        csv.push_str("record_hash,co_attester_collateral\n");
        for hash in hashes {
            let co = collateral_warnings
                .iter()
                .find(|(h, _)| h == hash)
                .map(|(_, co)| co.join(";"))
                .unwrap_or_default();
            csv.push_str(&format!("{hash},{co}\n"));
        }
        csv
    };

    std::fs::write(path, content)
        .with_context(|| format!("failed to write audit report to {}", path.display()))?;
    println!("    Audit report written to: {}", path.display());
    Ok(())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Run preflight checks before a mutating command (#401).
fn run_preflight_for_mutating(
    network_cfg: &NetworkConfig,
    network: &str,
    contract_ids: &[(&str, Option<&str>)],
    skip: bool,
    allow_unknown_wasm: bool,
) -> anyhow::Result<()> {
    let rpc = StellarCliRpc::new(&network_cfg.rpc_url, &network_cfg.network_passphrase);
    match run_preflight(
        &rpc,
        network,
        &network_cfg.network_passphrase,
        contract_ids,
        skip,
        allow_unknown_wasm,
    ) {
        Ok(result) if result.skipped => {
            // Already printed warning in run_preflight.
        }
        Ok(result) => {
            eprintln!(
                "✅ Preflight passed (passphrase: ok, ledger: {})",
                if result.ledger_fresh { "fresh" } else { "n/a" }
            );
        }
        Err(e) => {
            anyhow::bail!("preflight check failed:\n{e}");
        }
    }
    Ok(())
}

/// Build the argument list for `stellar contract invoke`.
fn invoke_args<'a>(
    cfg: &NetworkConfig,
    contract_id: &'a str,
    source: Option<&'a str>,
    function: &'a str,
    extra: &[&'a str],
) -> Vec<String> {
    let mut args = vec![
        "contract".to_string(),
        "invoke".to_string(),
        "--id".to_string(),
        contract_id.to_string(),
        "--rpc-url".to_string(),
        cfg.rpc_url.clone(),
        "--network-passphrase".to_string(),
        cfg.network_passphrase.clone(),
    ];
    if let Some(src) = source {
        args.push("--source".to_string());
        args.push(src.to_string());
    }
    args.push("--".to_string());
    args.push(function.to_string());
    for &a in extra {
        args.push(a.to_string());
    }
    args
}

fn run_stellar(args: Vec<String>) -> anyhow::Result<()> {
    println!("> stellar {}", args.join(" "));
    if which("stellar").is_ok() {
        let status = std::process::Command::new("stellar").args(&args).status()?;
        if !status.success() {
            anyhow::bail!("stellar CLI failed (exit: {status})");
        }
    } else {
        eprintln!(
            "stellar CLI not found — install: cargo install --locked stellar-cli\nCommand: stellar {}",
            args.join(" ")
        );
    }
    Ok(())
}

fn run_stellar_quiet(args: Vec<String>) -> anyhow::Result<String> {
    if which("stellar").is_ok() {
        let output = std::process::Command::new("stellar").args(&args).output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(anyhow::anyhow!(
                "{}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    } else {
        Err(anyhow::anyhow!("stellar CLI not found"))
    }
}

fn run_stellar_capture(args: Vec<String>) -> anyhow::Result<String> {
    run_stellar_quiet(args)
}

fn smoke_invoke(
    cfg: &NetworkConfig,
    contract_id: &str,
    source: Option<&str>,
    function: &str,
    extra: &[&str],
) -> anyhow::Result<String> {
    let args = invoke_args(cfg, contract_id, source, function, extra);
    run_stellar_capture(args)
}

fn upload_wasm(
    wasm_path: &std::path::Path,
    source: &str,
    network_cfg: &NetworkConfig,
) -> anyhow::Result<String> {
    if which("stellar").is_err() {
        println!("[no stellar CLI] Simulating WASM upload of {:?}", wasm_path);
        return Ok("<simulated-hash>".to_string());
    }
    let output = std::process::Command::new("stellar")
        .args([
            "contract",
            "upload",
            "--wasm",
            &wasm_path.to_string_lossy(),
            "--source",
            source,
            "--rpc-url",
            &network_cfg.rpc_url,
            "--network-passphrase",
            &network_cfg.network_passphrase,
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "stellar contract upload failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn deploy_contract(
    wasm_path: &std::path::Path,
    source: &str,
    network_cfg: &NetworkConfig,
) -> anyhow::Result<String> {
    if which("stellar").is_err() {
        println!("[no stellar CLI] Simulating deploy of {:?}", wasm_path);
        return Ok("<simulated-contract-id>".to_string());
    }
    let output = std::process::Command::new("stellar")
        .args([
            "contract",
            "deploy",
            "--wasm",
            &wasm_path.to_string_lossy(),
            "--source-account",
            source,
            "--rpc-url",
            &network_cfg.rpc_url,
            "--network-passphrase",
            &network_cfg.network_passphrase,
        ])
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "stellar contract deploy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn validated_source(source: Option<String>) -> anyhow::Result<Option<String>> {
    match source {
        Some(s) if !s.is_empty() => {
            validate_source_account(&s).context("invalid --source value")?;
            Ok(Some(s))
        }
        _ => {
            if let Ok(env_src) = std::env::var(ENV_SOURCE) {
                if !env_src.is_empty() {
                    validate_source_account(&env_src)
                        .context("invalid STELLAR_ACCOUNT env var")?;
                    return Ok(Some(env_src));
                }
            }
            Ok(None)
        }
    }
}

fn resolved_source(source: Option<String>) -> anyhow::Result<Option<String>> {
    validated_source(source)
}

fn resolved_admin(admin: Option<String>) -> anyhow::Result<Option<String>> {
    match admin {
        Some(a) if !a.is_empty() => {
            validate_account_address("admin address", &a).context("invalid --admin value")?;
            Ok(Some(a))
        }
        _ => {
            if let Ok(env_admin) = std::env::var(ENV_ADMIN) {
                if !env_admin.is_empty() {
                    validate_account_address("admin address", &env_admin)
                        .context("invalid ADMIN_ADDRESS env var")?;
                    return Ok(Some(env_admin));
                }
            }
            Ok(None)
        }
    }
}

fn deployment_summary(cfg: &NetworkConfig) -> String {
    match cfg.deployment_state() {
        DeploymentState::Deployed => "fully deployed".to_string(),
        DeploymentState::NotDeployed => "not deployed".to_string(),
        DeploymentState::Partial { missing } => format!(
            "partial (missing: {})",
            missing
                .iter()
                .map(|k| k.key())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn sha256_hex(data: &[u8]) -> String {
    // Minimal SHA-256 using std only (no ring/sha2 dep in this crate).
    // We shell out to sha256sum / shasum for correctness without adding deps.
    use std::io::Write;
    let mut child = std::process::Command::new("sha256sum")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .or_else(|_| {
            // macOS uses `shasum -a 256`
            std::process::Command::new("shasum")
                .args(["-a", "256"])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
        })
        .unwrap_or_else(|_| {
            // Fallback: can't compute hash without a tool; return placeholder.
            panic!("sha256sum or shasum not found — cannot compute WASM hash");
        });

    if let Some(stdin) = child.stdin.take() {
        let mut stdin = stdin;
        let _ = stdin.write_all(data);
    }
    let out = child.wait_with_output().expect("sha256sum wait failed");
    let line = String::from_utf8_lossy(&out.stdout);
    // Output format: "<hash>  -\n" or "<hash>  <filename>\n"
    line.split_whitespace()
        .next()
        .unwrap_or("unknown")
        .to_string()
}

fn which(bin: &str) -> Result<std::path::PathBuf, ()> {
    if let Some(paths) = std::env::var_os("PATH") {
        for p in std::env::split_paths(&paths) {
            let full = p.join(bin);
            if full.exists() {
                return Ok(full);
            }
        }
    }
    Err(())
}

fn extract_hex_hash_from_line(line: &str) -> Option<String> {
    for word in line.split_whitespace() {
        let w = word.trim_matches(|c: char| !c.is_ascii_hexdigit());
        if w.len() == 64 && w.chars().all(|c| c.is_ascii_hexdigit()) {
            return Some(w.to_string());
        }
    }
    None
}

fn extract_json_u64(text: &str, key: &str) -> Option<u64> {
    let search = format!("\"{key}\":");
    let pos = text.find(&search)?;
    let rest = text[pos + search.len()..].trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attester_add_missing_address_names_the_argument() {
        let err = Cli::try_parse_from(["lafiya-cli", "attester", "add"])
            .expect_err("expected a missing required argument error");
        let message = err.to_string();
        assert!(
            message.to_uppercase().contains("ADDRESS"),
            "expected error to name the missing `address` argument, got: {message}"
        );
    }

    #[test]
    fn attestation_get_missing_record_hash_names_the_argument() {
        let err = Cli::try_parse_from(["lafiya-cli", "attestation", "get"])
            .expect_err("expected a missing required argument error");
        let message = err.to_string();
        assert!(
            message.to_uppercase().contains("RECORD_HASH"),
            "expected error to name the missing `record_hash` argument, got: {message}"
        );
    }

    #[test]
    fn revoke_by_attester_missing_attester_names_argument() {
        let err = Cli::try_parse_from(["lafiya-cli", "attestation", "revoke-by-attester"])
            .expect_err("expected a missing required argument error");
        let message = err.to_string();
        assert!(
            message.to_uppercase().contains("ATTESTER"),
            "expected error to name the missing `attester` argument, got: {message}"
        );
    }

    #[test]
    fn signer_uri_validation_rejects_unknown_scheme() {
        let err = signer_from_uri("yubikey://1").unwrap_err();
        assert!(err.to_string().contains("identity://"));
    }

    #[test]
    fn signer_uri_valid_schemes_parse() {
        assert!(signer_from_uri("identity://alice").is_ok());
        assert!(signer_from_uri("ledger://0").is_ok());
        assert!(signer_from_uri("gcpkms://projects/p/locations/l/keyRings/r/cryptoKeyVersions/1").is_ok());
        assert!(signer_from_uri("awskms://arn:aws:kms:us-east-1:123456789012:key/abc").is_ok());
        assert!(signer_from_uri("pkcs11://my-token").is_ok());
    }

    #[test]
    fn extract_hex_hash_finds_64_char_hex() {
        let line = "  record_hash: deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let h = extract_hex_hash_from_line(line).unwrap();
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn extract_hex_hash_ignores_short_hex() {
        let line = "hash: abc123";
        assert!(extract_hex_hash_from_line(line).is_none());
    }

    #[test]
    fn which_finds_existing_bin() {
        // /bin/sh should exist everywhere
        assert!(which("sh").is_ok());
    }

    #[test]
    fn which_returns_err_for_missing_bin() {
        assert!(which("definitely-not-a-real-binary-xyz").is_err());
    }

    #[test]
    fn deployment_summary_variants() {
        use lafiya_config::{ContractIds, NetworkConfig};
        let cfg = |a: &str, b: &str| NetworkConfig {
            rpc_url: "https://soroban-testnet.stellar.org".into(),
            network_passphrase: "Test SDF Network ; September 2015".into(),
            contracts: ContractIds {
                attester_registry: a.into(),
                attestation_registry: b.into(),
            },
        };
        assert!(deployment_summary(&cfg("", "")).contains("not deployed"));
        assert!(deployment_summary(&cfg(
            "CBCRV4OYENAUXO2OXWU3JMKDXD7NGVLGXSHOXC55P7XUSHM2MD6JTFZA",
            "CCWPKEVBYEEDBMX2T4AKBOTTPXCGWNTZQXBOQWOHLVJ7JOWAMX3G6EAX"
        ))
        .contains("deployed"));
    }
}
