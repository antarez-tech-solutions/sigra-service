//! Signer capability tokens gate the sign route (closes F1, signer-facing).
//! Requires MongoDB on localhost:27017 (override: SIGRA_TEST_MONGODB_URI).

use reqwest::StatusCode;
use tokio::net::TcpListener;

fn mongo_uri() -> String {
    std::env::var("SIGRA_TEST_MONGODB_URI").unwrap_or_else(|_| "mongodb://localhost:27017".into())
}

async fn start_server() -> std::net::SocketAddr {
    let uri = mongo_uri();
    // SAFETY: single-threaded test setup before server starts.
    unsafe {
        std::env::set_var("MONGODB_URI", uri);
        std::env::set_var("MONGODB_DATABASE", "sigra_test");
        std::env::set_var("S3_BUCKET", "sigra-test");
        std::env::set_var("S3_ENDPOINT", "http://localhost:9000");
        std::env::set_var("S3_REGION", "us-east-1");
        std::env::set_var("EAS_RPC_URL", "https://mainnet.base.org");
        std::env::set_var(
            "EAS_PRIVATE_KEY",
            "0000000000000000000000000000000000000000000000000000000000000001",
        );
        std::env::set_var(
            "EAS_SCHEMA_UID",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        std::env::set_var("ANCHOR_INTERVAL_SECS", "99999");
        std::env::set_var("GATEWAY_SHARED_SECRET", "test-gateway-secret");
        std::env::set_var("ADMIN_TOKEN", "test-admin-token");
        std::env::set_var("SIGNER_TOKEN_SECRET", "test-signer-token-secret");
    }

    let app = sigra_service::app().await.expect("build app");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

/// Seed a Draft envelope + one pending signer directly, returning their ids.
/// Avoids the S3-dependent upload path. No document row is needed: neither
/// send_envelope nor sign_envelope reads the document in this phase.
async fn seed(db: &mongodb::Database) -> (String, String) {
    let env_id = uuid::Uuid::new_v4().to_string();
    let signer_id = uuid::Uuid::new_v4().to_string();
    let doc_id = uuid::Uuid::new_v4().to_string();
    // The models serialize chrono DateTime<Utc> via serde -> RFC3339 STRING
    // (not a BSON date), so seed strings to match how the app writes rows.
    let now = chrono::Utc::now().to_rfc3339();

    db.collection::<bson::Document>("envelopes")
        .insert_one(bson::doc! {
            "_id": &env_id, "document_id": &doc_id, "owner_id": "owner-1",
            "title": "t", "status": "draft", "signing_order": "parallel",
            "deadline": null, "attestation_uid": null, "merkle_root": null,
            "merkle_proof": null, "created_at": &now, "updated_at": &now,
        })
        .await
        .unwrap();
    db.collection::<bson::Document>("signers")
        .insert_one(bson::doc! {
            "_id": &signer_id, "envelope_id": &env_id, "email": "s@example.com",
            "wallet_address": null, "name": "S", "order": 1_i32,
            "status": "pending", "signed_at": null, "signature_data": null,
            "token_hash": null,
        })
        .await
        .unwrap();

    (env_id, signer_id)
}

#[tokio::test]
async fn sign_requires_valid_capability_token() {
    let addr = start_server().await;
    let db = mongodb::Client::with_uri_str(mongo_uri())
        .await
        .unwrap()
        .database("sigra_test");
    let (env_id, signer_id) = seed(&db).await;
    let http = reqwest::Client::new();

    // Send (owner route): transitions Draft -> Pending and returns tokens.
    let resp = http
        .post(format!("http://{addr}/api/envelopes/{env_id}/send"))
        .header("x-gateway-auth", "test-gateway-secret")
        .header("x-user-uuid", "owner-1")
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "send failed: {body}");
    let token = body["signing_tokens"][&signer_id].as_str().unwrap().to_string();

    // Sign without a token -> 401.
    let resp = http
        .post(format!("http://{addr}/api/envelopes/{env_id}/sign"))
        .json(&serde_json::json!({ "signer_id": signer_id, "signature_data": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Sign with a token whose signer_id does not match the body -> 403.
    let resp = http
        .post(format!("http://{addr}/api/envelopes/{env_id}/sign"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "signer_id": "someone-else", "signature_data": "x" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Valid token -> 200, envelope completes (single signer).
    let resp = http
        .post(format!("http://{addr}/api/envelopes/{env_id}/sign"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "signer_id": signer_id, "signature_data": "sig-blob" }))
        .send()
        .await
        .unwrap();
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(status, StatusCode::OK, "sign failed: {body}");
    assert_eq!(body["envelope_completed"], true);

    // Replay the same token -> rejected (signer no longer pending).
    let resp = http
        .post(format!("http://{addr}/api/envelopes/{env_id}/sign"))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "signer_id": signer_id, "signature_data": "again" }))
        .send()
        .await
        .unwrap();
    assert_ne!(resp.status(), StatusCode::OK);
}
