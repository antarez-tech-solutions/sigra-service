//! Generate a keypair and sign a canonical payload.
//! Usage: cargo run --example sign_payload -- <envelope_id> <document_hash> <signer_id>

use sigra_service::binding::canonical_payload;
use sigrachain_crypto::SigningKeyPair;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (env_id, doc_hash, signer_id) = (&args[1], &args[2], &args[3]);
    let signed_at = chrono::Utc::now().to_rfc3339();

    let kp = SigningKeyPair::generate().unwrap();
    let payload = canonical_payload(env_id, doc_hash, signer_id, &signed_at);
    let sig = kp.sign(&payload);

    println!("register this as the signer's wallet_address:");
    println!("  {}", kp.public_key_hex());
    println!("request body:");
    println!(
        "{}",
        serde_json::json!({
            "signer_id": signer_id,
            "signature": {
                "algorithm": "ed25519",
                "public_key_hex": kp.public_key_hex(),
                "signature_hex": sig.to_hex(),
                "signed_at": signed_at,
            }
        })
    );
}
