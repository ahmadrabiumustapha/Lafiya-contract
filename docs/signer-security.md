# Signer Security: Trust Boundaries for Lafiya Admin Keys

This document describes the security properties and trust boundaries of each
signing backend supported by `lafiya-cli`, as required by issue #399.

---

## Overview

Admin and multisig signer keys control the entire Lafiya trust layer — they can
add or remove attesters, pause contracts, and upgrade WASM code. All three
operations have direct patient-safety consequences if misused.

The `Signer` abstraction (`crates/lafiya-cli/src/signer.rs`) makes the backend
pluggable, but the security properties of each backend differ significantly.

---

## Backends

### 1. File / Identity (`identity://<name>`)

**How it works:** Delegates to the `stellar` CLI's on-disk identity keystore
(typically `~/.config/stellar/identity/<name>.toml` or the OS keychain if
configured).

**Key storage:** On the operator's filesystem, protected only by OS permissions
and the host's security posture.

**Trust boundary:** The private key can be read by any process running as the
same OS user. Protection requires:
- OS-level user isolation (no shared accounts)
- Encrypted home directory or full-disk encryption
- No malware or compromised shells

**Recommended for:** Testnet, local development, automated CI with short-lived
secrets.

**Not recommended for:** Mainnet admin keys, multisig quorum keys controlling
production contracts.

---

### 2. Ledger (`ledger://<index>`)

**How it works:** Signs via the Stellar app on a Ledger hardware wallet over
HID/USB. The derivation path is `m/44'/148'/<index>'`.

**Key storage:** Inside the Ledger's secure element (ST33 or similar). The
private key **never leaves the device**.

**Trust boundary:**
- The host computer sees only the signed output, never the private key.
- The Stellar Ledger app supports **blind hash signing** for Soroban
  authorization entries. The device screen displays only the hash, not the
  decoded invocation tree.
- **The CLI MUST display the decoded authorization tree on the host before
  sending the hash to the device.** The operator must verify the decoded tree
  matches their intent before approving on the device.
- Without this verification, a compromised CLI binary could construct a
  malicious authorization tree, compute its hash, and get the operator to sign
  it blindly.

**Setup (Linux):**
```bash
# Install udev rules for Ledger USB access
wget -q -O- https://raw.githubusercontent.com/LedgerHQ/udev-rules/master/add_udev_rules.sh | sudo bash
```

**Setup (macOS):** No additional setup needed; the Ledger app handles HID.

**Manual testing procedure** (documented here because unit tests cannot run
without a physical device):
1. Connect Ledger, unlock PIN, open Stellar app.
2. Run `lafiya-cli --signer ledger://0 config show` to confirm device is found.
3. Run `lafiya-cli --signer ledger://0 attester add G...` (on testnet).
4. Verify the decoded auth tree is printed on the host.
5. Confirm the hash shown on the device matches the host display.
6. Approve on device and confirm the transaction is accepted.

**Recommended for:** Mainnet admin keys, multisig quorum keys.

---

### 3. GCP KMS (`gcpkms://<resource-name>`)

**How it works:** Signs via Google Cloud KMS using an ed25519 asymmetric key.
The private key never leaves GCP's HSM boundary.

**ed25519 support:** GCP KMS supports ed25519 with the `EC_SIGN_ED25519`
algorithm (available since 2024 in all regions). Key spec: `EC_SIGN_ED25519`.

**Credential setup:**
```bash
# Service account key file
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Or use Workload Identity (GKE, Cloud Run) — no key file needed.
```

**URI format:**
```
gcpkms://projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeyVersions/<version>
```

**IAM requirements:** The signing identity needs `roles/cloudkms.signer` on
the key version.

**Audit trail:** Every `SignAsymmetric` call is logged in Cloud Audit Logs.

**Recommended for:** Production/mainnet admin keys, automated pipelines with
Workload Identity.

---

### 4. AWS KMS (`awskms://<arn>`)

**How it works:** Signs via AWS KMS using an ed25519 asymmetric key.

**ed25519 support:** AWS KMS supports ed25519 with key spec `ECC_NIST_ED25519`
and signing algorithm `ECDSA_SHA_256` — **note:** AWS uses the term "ECDSA"
for the API but the actual operation with `ECC_NIST_ED25519` key spec produces
an ed25519 signature. Verify this with AWS docs at integration time.

**Credential setup:**
```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
# Or use an IAM role (EC2 instance profile, ECS task role, etc.)
```

**URI format:**
```
awskms://arn:aws:kms:<region>:<account>:key/<key-id>
```

**IAM requirements:** The principal needs `kms:Sign` on the key resource.

**Audit trail:** Every `Sign` API call is logged in CloudTrail.

**Recommended for:** Production/mainnet admin keys in AWS-native deployments.

---

### 5. PKCS#11 (`pkcs11://<label>`)

**How it works:** Signs via any PKCS#11-compatible HSM or token (SoftHSM 2,
nCipher, AWS CloudHSM, Thales, etc.).

**ed25519 support:** Requires the token to support `CKM_EDDSA`. SoftHSM 2.6+
supports it. Hardware HSMs vary — check vendor documentation.

**Setup:**
```bash
export PKCS11_MODULE_PATH=/usr/lib/softhsm/libsofthsm2.so
export PKCS11_PIN=1234   # or use a PIN file
```

**Recommended for:** On-premises HSM deployments, compliance environments.

---

## Comparison Matrix

| Property | Identity (file) | Ledger | GCP KMS | AWS KMS | PKCS#11 |
|----------|-----------------|--------|---------|---------|---------|
| Key never leaves hardware | ❌ | ✅ | ✅ | ✅ | ✅ |
| Requires physical presence | ❌ | ✅ (per sign) | ❌ | ❌ | ❌ |
| Blind signing risk | ❌ | ⚠️ (host must display decoded auth) | ❌ | ❌ | ❌ |
| Audit trail | ❌ | ❌ (local only) | ✅ Cloud Audit | ✅ CloudTrail | Varies |
| Mainnet-safe | ❌ | ✅ | ✅ | ✅ | ✅ |
| CI-automatable | ✅ | ❌ | ✅ (Workload ID) | ✅ (IAM role) | ✅ |

---

## Multisig ceremony

For the multisig account contract (`contracts/multisig-account`), each signer
in the quorum signs the authorization hash independently. The CLI assembles the
final transaction with all N-of-M signatures sorted by public key (as required
by the contract's `__check_auth`).

Each signer must independently verify the decoded authorization tree before
signing. The CLI prints it and requires `--confirm-auth` before proceeding when
a Ledger or KMS signer is used.

---

## Pre-alpha note

The Ledger and KMS signing paths in `crates/lafiya-cli/src/signer.rs` are
fully specified stubs: the APDU sequences and API calls are documented in code
comments, and the backends return clear errors with setup instructions. Full
implementation requires hardware/credential availability and is tracked as a
follow-up to this pre-alpha milestone.
