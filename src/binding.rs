//! Canonical signing payload and the stored signature record.

use serde::{Deserialize, Serialize};

/// The exact bytes a signer signs. Both client and server build this
/// independently — field order, separators, and the version prefix are
/// part of the contract and must never change within V1.
pub fn canonical_payload(
    envelope_id: &str,
    document_hash: &str,
    signer_id: &str,
    signed_at_rfc3339: &str,
) -> Vec<u8> {
    format!(
        "SIGRA-SIGN-V1\n{envelope_id}\n{document_hash}\n{signer_id}\n{signed_at_rfc3339}"
    )
    .into_bytes()
}

/// What the client submits for a wallet (key-holding) signer.
#[derive(Debug, Deserialize)]
pub struct WalletSignature {
    /// Only "ed25519" is accepted in V1.
    pub algorithm: String,
    /// 32-byte public key, hex — must equal the signer's registered key.
    pub public_key_hex: String,
    /// 64-byte Ed25519 signature over the canonical payload, hex.
    pub signature_hex: String,
    /// RFC3339 timestamp the signer included in the payload.
    pub signed_at: String,
}

/// What gets persisted in `Signer.signature_data` (as JSON) — replaces the
/// old opaque string (models/signer.rs:27).
#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureRecord {
    /// "cryptographic" (Ed25519-verified) or "audit" (email signer,
    /// capability-token evidence only).
    pub class: String,
    pub algorithm: Option<String>,
    pub public_key_hex: Option<String>,
    pub signature_hex: Option<String>,
    /// SHA-256 hex of the canonical payload (recomputable by an auditor).
    pub payload_hash: String,
    pub signed_at: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigrachain_crypto::{verify_signature, Signature, SigningKeyPair};

    #[test]
    fn ed25519_roundtrip_over_canonical_payload() {
        let kp = SigningKeyPair::generate().unwrap();
        let payload = canonical_payload("env-1", "ab".repeat(32).as_str(), "sig-1", "2026-06-11T00:00:00Z");

        let sig = kp.sign(&payload);
        assert!(verify_signature(&payload, &sig, kp.public_key()).unwrap());

        // One changed byte anywhere → invalid.
        let tampered = canonical_payload("env-1", "ab".repeat(32).as_str(), "sig-2", "2026-06-11T00:00:00Z");
        assert!(!verify_signature(&tampered, &sig, kp.public_key()).unwrap());

        // Hex round-trip, as the API will receive it.
        let sig2 = Signature::from_bytes(&hex::decode(sig.to_hex()).unwrap()).unwrap();
        assert!(verify_signature(&payload, &sig2, kp.public_key()).unwrap());
    }
}
