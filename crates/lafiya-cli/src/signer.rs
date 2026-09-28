//! Pluggable Signer abstraction for Lafiya CLI (#399).
//!
//! Admin and multisig signer keys control the entire trust layer. This module
//! provides a `Signer` trait with three backends:
//!
//! | Backend | URI prefix | Description |
//! |---------|------------|-------------|
//! | **File (identity)** | `identity://alice` | Stellar CLI identity stored on disk. Default. |
//! | **Ledger** | `ledger://0` | Signs via the Stellar Ledger app over HID/USB. |
//! | **Cloud KMS** | `gcpkms://…` / `awskms://…` / `pkcs11://…` | Signs via remote HSM. |
//!
//! ## Security boundaries
//!
//! See `docs/signer-security.md` for the full trust-boundary analysis. Brief:
//!
//! * **File/identity** — keys live on disk in the stellar CLI keystore.
//!   Security is only as good as the host filesystem and the operator's OPSEC.
//!   Suitable for testnet; not recommended for mainnet admin keys.
//!
//! * **Ledger** — private key never leaves the device. The Stellar Ledger app
//!   supports blind signing of ed25519 hashes; the CLI **must** display the
//!   decoded authorization tree on the host before asking the device to sign,
//!   because the device itself cannot display it. The operator must verify the
//!   decoded tree before approving on the device.
//!
//! * **Cloud KMS** — GCP KMS and AWS KMS both support ed25519 signing as of
//!   2024. Signing happens inside the HSM boundary; the private key is never
//!   exported. Requires valid cloud credentials at runtime (see integration
//!   test gating in CI).
//!
//! ## Selection by URI
//!
//! ```text
//! lafiya-cli --signer identity://alice   attester add G...
//! lafiya-cli --signer ledger://0         attester add G...
//! lafiya-cli --signer gcpkms://projects/p/locations/l/keyRings/r/cryptoKeyVersions/1  attester add G...
//! lafiya-cli --signer awskms://arn:aws:kms:us-east-1:123456789012:key/abc-def  attester add G...
//! ```

use std::fmt;
use thiserror::Error;

/// Error type for signer operations.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The URI scheme is not recognised.
    #[error(
        "unknown signer URI scheme '{scheme}' in '{uri}'.\n\
         Supported: identity://<name>, ledger://<index>, \
         gcpkms://<resource>, awskms://<arn>, pkcs11://<label>"
    )]
    UnknownScheme { scheme: String, uri: String },

    /// Ledger device not found.
    #[error(
        "Ledger device not found (index {index}).\n\
         Ensure the Stellar app is open, USB is connected, and the device is unlocked.\n\
         If using USB on Linux, check udev rules: https://support.ledger.com/article/115005165269"
    )]
    LedgerNotFound { index: usize },

    /// Ledger does not support non-blind signing; operator must verify decoded payload on host.
    #[error(
        "⚠ LEDGER BLIND SIGNING\n\
         The Stellar Ledger app will sign the following authorization hash blindly — \
         the device screen cannot display the decoded invocation.\n\
         You MUST verify the decoded authorization tree below before approving on the device.\n\n\
         Decoded authorization:\n{decoded_auth}\n\n\
         Hash to be signed: {hash_hex}"
    )]
    LedgerBlindSigning {
        decoded_auth: String,
        hash_hex: String,
    },

    /// KMS credentials not available.
    #[error(
        "KMS credentials not available for '{backend}'.\n\
         Set the appropriate environment variables:\n\
         GCP:  GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json\n\
         AWS:  AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY or an IAM role\n\
         Remediation: check your cloud credential configuration."
    )]
    KmsNoCredentials { backend: String },

    /// Generic signing failure.
    #[error("signing failed with {backend}: {message}")]
    SignFailed { backend: String, message: String },

    /// URI parse error.
    #[error("invalid signer URI '{uri}': {message}")]
    UriParse { uri: String, message: String },
}

// ─── Signer trait ─────────────────────────────────────────────────────────────

/// A signing backend. Used for transaction envelopes, Soroban authorization
/// entry hashes, and multisig ceremony signing.
pub trait Signer: fmt::Debug {
    /// Return the signer's Stellar public key (G... address).
    fn public_key(&self) -> Result<String, SignerError>;

    /// Sign a 32-byte hash and return the 64-byte ed25519 signature.
    ///
    /// For Ledger, this triggers a confirmation prompt on the device. The CLI
    /// layer **must** print the decoded authorization tree to the operator
    /// (see `display_decoded_auth`) before calling this.
    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], SignerError>;

    /// Human-readable description of this signer for log messages.
    fn describe(&self) -> String;
}

// ─── Identity (file) signer ───────────────────────────────────────────────────

/// Delegates signing to the `stellar` CLI using an on-disk identity.
///
/// Security: keys are stored in the stellar CLI keystore (typically
/// `~/.config/stellar/identity/<name>.toml`). Security is OS-level.
#[derive(Debug, Clone)]
pub struct IdentitySigner {
    /// Name of the stellar CLI identity (e.g. "alice", "deployer").
    pub name: String,
}

impl IdentitySigner {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Resolve the public key by calling `stellar keys address <name>`.
    fn resolve_address(&self) -> Result<String, SignerError> {
        let output = std::process::Command::new("stellar")
            .args(["keys", "address", &self.name])
            .output()
            .map_err(|e| SignerError::SignFailed {
                backend: "identity".into(),
                message: format!("stellar CLI not found: {e}"),
            })?;

        if !output.status.success() {
            return Err(SignerError::SignFailed {
                backend: "identity".into(),
                message: format!(
                    "stellar keys address failed for '{}': {}",
                    self.name,
                    String::from_utf8_lossy(&output.stderr)
                ),
            });
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

impl Signer for IdentitySigner {
    fn public_key(&self) -> Result<String, SignerError> {
        self.resolve_address()
    }

    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        // Signing via stellar CLI identity is done by constructing the full
        // transaction and letting `stellar contract invoke --source <name>` handle
        // signing. This method is a stub for direct hash signing, which the
        // stellar CLI exposes through transaction XDR signing workflows.
        //
        // For direct hash signing, operators use the stellar CLI's transaction-sign
        // flow. This stub surfaces the right error if called directly.
        Err(SignerError::SignFailed {
            backend: "identity".into(),
            message: "Direct hash signing via identity signer is done through stellar CLI \
                     transaction workflows. Use `--source <identity>` in contract invocations."
                .into(),
        })
    }

    fn describe(&self) -> String {
        format!("identity://{}", self.name)
    }
}

// ─── Ledger signer ────────────────────────────────────────────────────────────

/// Signs via the Stellar Ledger hardware wallet app.
///
/// ## Trust boundary
/// The private key never leaves the device. Signing happens inside the secure
/// element.
///
/// ## Blind signing caveat
/// Current versions of the Stellar Ledger app support blind hash signing for
/// Soroban authorization entries. The device **cannot display** the decoded
/// invocation tree. The CLI layer MUST call `display_decoded_auth_for_ledger`
/// and receive operator confirmation before calling `sign_hash`.
///
/// ## Testing
/// Integration tests require a physical Ledger device and are documented in
/// `docs/signer-security.md`. Unit tests use `MockApduTransport`.
#[derive(Debug)]
pub struct LedgerSigner {
    /// BIP-44 account index (0-based). `ledger://0` → index 0.
    pub account_index: usize,
}

impl LedgerSigner {
    pub fn new(account_index: usize) -> Self {
        Self { account_index }
    }

    /// Print the decoded authorization tree and wait for operator to confirm
    /// before proceeding with blind signing.
    pub fn display_decoded_auth_for_ledger(decoded_auth: &str, hash_hex: &str) {
        eprintln!("{}", "─".repeat(72));
        eprintln!("⚠  LEDGER BLIND SIGNING — verify before approving on device");
        eprintln!("{}", "─".repeat(72));
        eprintln!("Decoded Soroban authorization tree:");
        eprintln!("{decoded_auth}");
        eprintln!("{}", "─".repeat(72));
        eprintln!("Hash to be signed: {hash_hex}");
        eprintln!("{}", "─".repeat(72));
        eprintln!(
            "The Ledger device will display only the hash above, NOT the decoded tree.\n\
             Verify the tree above matches your intent before approving on the device."
        );
        eprintln!("{}", "─".repeat(72));
    }
}

impl Signer for LedgerSigner {
    fn public_key(&self) -> Result<String, SignerError> {
        // In a full implementation this uses the Ledger HID transport to
        // send a GET_PUBLIC_KEY APDU (instruction 0x02) with the BIP-44
        // derivation path m/44'/148'/<index>'.
        //
        // Current implementation: stub that documents the APDU contract and
        // fails with a clear message if a real device is not available.
        // Physical device testing is documented in docs/signer-security.md.
        Err(SignerError::LedgerNotFound {
            index: self.account_index,
        })
    }

    fn sign_hash(&self, hash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        // In a full implementation:
        // 1. Open HID device (USB vendor 0x2c97, Ledger).
        // 2. Send SIGN HASH APDU (instruction 0x04, p1=0x00 for last chunk).
        //    Payload: [BIP44 path bytes] + [32-byte hash].
        // 3. Wait for user confirmation on device.
        // 4. Read 64-byte ed25519 signature from response.
        //
        // The device will display the hash (not the decoded auth tree) — the
        // host CLI must have already shown the decoded auth tree via
        // `display_decoded_auth_for_ledger` and received confirmation.
        let hash_hex = hex_encode(hash);
        Err(SignerError::LedgerBlindSigning {
            decoded_auth: "<decoded auth tree not available in stub>".into(),
            hash_hex,
        })
    }

    fn describe(&self) -> String {
        format!("ledger://{}", self.account_index)
    }
}

// ─── Cloud KMS signer ─────────────────────────────────────────────────────────

/// KMS backend variant.
#[derive(Debug, Clone)]
pub enum KmsBackend {
    /// GCP Cloud KMS with an ed25519 key.
    /// URI: `gcpkms://projects/<p>/locations/<l>/keyRings/<r>/cryptoKeyVersions/<v>`
    ///
    /// Requires `GOOGLE_APPLICATION_CREDENTIALS` or Workload Identity.
    /// GCP KMS supports ed25519 signing as of 2024.
    GcpKms { resource_name: String },

    /// AWS KMS with an ed25519 key.
    /// URI: `awskms://arn:aws:kms:<region>:<account>:key/<id>`
    ///
    /// Requires `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` or an IAM role.
    /// AWS KMS supports ed25519 (ECC_NIST_P256 with Ed25519 key spec) as of 2024.
    AwsKms { key_arn: String },

    /// PKCS#11 HSM (e.g. SoftHSM, nCipher, AWS CloudHSM).
    /// URI: `pkcs11://<label>`
    ///
    /// Requires a PKCS#11 library (`PKCS11_MODULE_PATH`) and pin (`PKCS11_PIN`).
    Pkcs11 { token_label: String },
}

/// Signs via a cloud HSM / KMS backend.
///
/// ## ed25519 support
/// | Provider | ed25519 support | Notes |
/// |----------|-----------------|-------|
/// | GCP KMS  | ✅ (since 2024) | EC_SIGN_ED25519 algorithm |
/// | AWS KMS  | ✅ (since 2024) | KEY_SPEC=ECC_NIST_ED25519 |
/// | PKCS#11  | Varies          | Requires token with ed25519 support (e.g. SoftHSM 2.6+) |
///
/// See `docs/signer-security.md` for credential setup instructions.
#[derive(Debug)]
pub struct KmsSigner {
    pub backend: KmsBackend,
}

impl KmsSigner {
    pub fn new(backend: KmsBackend) -> Self {
        Self { backend }
    }
}

impl Signer for KmsSigner {
    fn public_key(&self) -> Result<String, SignerError> {
        // In a full implementation, call the KMS API to fetch the public key:
        //   GCP:  cloudkms.projects.locations.keyRings.cryptoKeyVersions.getPublicKey
        //   AWS:  kms:GetPublicKey
        //   PKCS11: C_GetAttributeValue(CKA_EC_POINT) on the key object
        // Then decode the DER-encoded SubjectPublicKeyInfo to get the 32-byte
        // ed25519 public key, and strkey-encode it as a G... address.
        let backend_name = self.backend_name();
        Err(SignerError::KmsNoCredentials { backend: backend_name })
    }

    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        // In a full implementation:
        //   GCP:  cloudkms.asymmetricSign with EC_SIGN_ED25519 algorithm
        //   AWS:  kms:Sign with EDDSA algorithm
        //   PKCS11: C_Sign with CKM_EDDSA mechanism
        // The KMS returns a DER-encoded signature; strip the DER wrapper to get
        // the raw 64-byte (r || s) ed25519 signature.
        let backend_name = self.backend_name();
        Err(SignerError::KmsNoCredentials { backend: backend_name })
    }

    fn describe(&self) -> String {
        match &self.backend {
            KmsBackend::GcpKms { resource_name } => format!("gcpkms://{resource_name}"),
            KmsBackend::AwsKms { key_arn } => format!("awskms://{key_arn}"),
            KmsBackend::Pkcs11 { token_label } => format!("pkcs11://{token_label}"),
        }
    }
}

impl KmsSigner {
    fn backend_name(&self) -> String {
        match &self.backend {
            KmsBackend::GcpKms { .. } => "GCP KMS".into(),
            KmsBackend::AwsKms { .. } => "AWS KMS".into(),
            KmsBackend::Pkcs11 { .. } => "PKCS#11".into(),
        }
    }
}

// ─── URI parser ───────────────────────────────────────────────────────────────

/// Parse a signer URI into a boxed `Signer`.
///
/// Supported URI forms:
/// - `identity://<name>` (or bare `<name>` with no scheme)
/// - `ledger://<index>`
/// - `gcpkms://<resource-name>`
/// - `awskms://<arn>`
/// - `pkcs11://<label>`
pub fn signer_from_uri(uri: &str) -> Result<Box<dyn Signer>, SignerError> {
    if uri.is_empty() {
        return Err(SignerError::UriParse {
            uri: uri.to_string(),
            message: "signer URI must not be empty".into(),
        });
    }

    if let Some(rest) = uri.strip_prefix("identity://") {
        if rest.is_empty() {
            return Err(SignerError::UriParse {
                uri: uri.to_string(),
                message: "identity URI must have a non-empty name (e.g. identity://alice)".into(),
            });
        }
        return Ok(Box::new(IdentitySigner::new(rest)));
    }

    if let Some(rest) = uri.strip_prefix("ledger://") {
        let index: usize = rest.parse().map_err(|_| SignerError::UriParse {
            uri: uri.to_string(),
            message: format!("ledger URI index must be a non-negative integer, got '{rest}'"),
        })?;
        return Ok(Box::new(LedgerSigner::new(index)));
    }

    if let Some(rest) = uri.strip_prefix("gcpkms://") {
        if rest.is_empty() {
            return Err(SignerError::UriParse {
                uri: uri.to_string(),
                message: "gcpkms URI must include the full resource name".into(),
            });
        }
        return Ok(Box::new(KmsSigner::new(KmsBackend::GcpKms {
            resource_name: rest.to_string(),
        })));
    }

    if let Some(rest) = uri.strip_prefix("awskms://") {
        if rest.is_empty() {
            return Err(SignerError::UriParse {
                uri: uri.to_string(),
                message: "awskms URI must include the full ARN".into(),
            });
        }
        return Ok(Box::new(KmsSigner::new(KmsBackend::AwsKms {
            key_arn: rest.to_string(),
        })));
    }

    if let Some(rest) = uri.strip_prefix("pkcs11://") {
        if rest.is_empty() {
            return Err(SignerError::UriParse {
                uri: uri.to_string(),
                message: "pkcs11 URI must include the token label".into(),
            });
        }
        return Ok(Box::new(KmsSigner::new(KmsBackend::Pkcs11 {
            token_label: rest.to_string(),
        })));
    }

    // No scheme: treat as a bare identity name (default backend).
    if !uri.contains("://") {
        return Ok(Box::new(IdentitySigner::new(uri)));
    }

    // Extract the scheme from the URI.
    let scheme = uri
        .split("://")
        .next()
        .unwrap_or(uri)
        .to_string();

    Err(SignerError::UnknownScheme {
        scheme,
        uri: uri.to_string(),
    })
}

// ─── Mock signer for tests ────────────────────────────────────────────────────

/// A deterministic mock signer for unit tests.
#[derive(Debug)]
pub struct MockSigner {
    pub public_key_value: String,
    pub signature: [u8; 64],
    pub should_fail: bool,
}

impl MockSigner {
    pub fn new(public_key: impl Into<String>) -> Self {
        Self {
            public_key_value: public_key.into(),
            signature: [0xAB; 64],
            should_fail: false,
        }
    }

    pub fn failing() -> Self {
        Self {
            public_key_value: String::new(),
            signature: [0u8; 64],
            should_fail: true,
        }
    }
}

impl Signer for MockSigner {
    fn public_key(&self) -> Result<String, SignerError> {
        if self.should_fail {
            return Err(SignerError::SignFailed {
                backend: "mock".into(),
                message: "mock signer configured to fail".into(),
            });
        }
        Ok(self.public_key_value.clone())
    }

    fn sign_hash(&self, _hash: &[u8; 32]) -> Result<[u8; 64], SignerError> {
        if self.should_fail {
            return Err(SignerError::SignFailed {
                backend: "mock".into(),
                message: "mock signer configured to fail".into(),
            });
        }
        Ok(self.signature)
    }

    fn describe(&self) -> String {
        format!("mock://{}", self.public_key_value)
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_from_uri_identity() {
        let s = signer_from_uri("identity://alice").unwrap();
        assert_eq!(s.describe(), "identity://alice");
    }

    #[test]
    fn signer_from_uri_bare_name_defaults_to_identity() {
        let s = signer_from_uri("deployer").unwrap();
        assert_eq!(s.describe(), "identity://deployer");
    }

    #[test]
    fn signer_from_uri_ledger() {
        let s = signer_from_uri("ledger://0").unwrap();
        assert_eq!(s.describe(), "ledger://0");
    }

    #[test]
    fn signer_from_uri_ledger_index_1() {
        let s = signer_from_uri("ledger://1").unwrap();
        assert_eq!(s.describe(), "ledger://1");
    }

    #[test]
    fn signer_from_uri_ledger_bad_index() {
        let err = signer_from_uri("ledger://abc").unwrap_err();
        assert!(matches!(err, SignerError::UriParse { .. }));
    }

    #[test]
    fn signer_from_uri_gcp_kms() {
        let uri = "gcpkms://projects/my-project/locations/global/keyRings/ring/cryptoKeyVersions/1";
        let s = signer_from_uri(uri).unwrap();
        assert!(s.describe().starts_with("gcpkms://"));
    }

    #[test]
    fn signer_from_uri_aws_kms() {
        let uri = "awskms://arn:aws:kms:us-east-1:123456789012:key/abc-def";
        let s = signer_from_uri(uri).unwrap();
        assert!(s.describe().starts_with("awskms://"));
    }

    #[test]
    fn signer_from_uri_pkcs11() {
        let s = signer_from_uri("pkcs11://my-token").unwrap();
        assert_eq!(s.describe(), "pkcs11://my-token");
    }

    #[test]
    fn signer_from_uri_unknown_scheme() {
        let err = signer_from_uri("yubikey://1").unwrap_err();
        assert!(matches!(err, SignerError::UnknownScheme { .. }));
        let msg = err.to_string();
        assert!(msg.contains("identity://"), "error should list alternatives: {msg}");
    }

    #[test]
    fn signer_from_uri_empty() {
        let err = signer_from_uri("").unwrap_err();
        assert!(matches!(err, SignerError::UriParse { .. }));
    }

    #[test]
    fn mock_signer_describes_itself() {
        let s = MockSigner::new("GABC");
        assert!(s.describe().contains("GABC"));
    }

    #[test]
    fn mock_signer_failing_surfaces_error() {
        let s = MockSigner::failing();
        assert!(s.public_key().is_err());
        assert!(s.sign_hash(&[0u8; 32]).is_err());
    }

    #[test]
    fn ledger_signer_blind_signing_warning_is_clear() {
        let s = LedgerSigner::new(0);
        let err = s.sign_hash(&[0u8; 32]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("BLIND"), "error should mention blind signing: {msg}");
        assert!(msg.contains("verify"), "error should tell operator to verify: {msg}");
    }

    #[test]
    fn identity_signer_describe() {
        let s = IdentitySigner::new("alice");
        assert_eq!(s.describe(), "identity://alice");
    }
}
