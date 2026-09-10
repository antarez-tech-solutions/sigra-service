//! Auth integration tests: authenticated requests carry X-User-UUID.
//! Requires MongoDB on localhost:27017 (override: SIGRA_TEST_MONGODB_URI).

use reqwest::StatusCode;
use tokio::net::TcpListener;

async fn start_server() -> std::net::SocketAddr {
    let mongo_uri = std::env::var("SIGRA_TEST_MONGODB_URI")
        .unwrap_or_else(|_| "mongodb://localhost:27017".into());
    // SAFETY: single-threaded test setup before server starts; no concurrent env reads.
    unsafe {
        std::env::set_var("MONGODB_URI", mongo_uri);
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
        // Large interval so the anchor loop never fires during tests.
        std::env::set_var("ANCHOR_INTERVAL_SECS", "99999");
        std::env::set_var("SIGNER_TOKEN_SECRET", "test-signer-token-secret");
    }

    let app = sigra_service::app().await.expect("build app");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn admin_anchor_requires_user_header() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // No X-User-UUID → 403 (forbidden by the AuthenticatedUser extractor).
    let resp = client
        .post(format!("http://{addr}/admin/anchor"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // With X-User-UUID → 200 (empty anchor when no completed envelopes).
    let resp = client
        .post(format!("http://{addr}/admin/anchor"))
        .header("x-user-uuid", "11111111-1111-1111-1111-111111111111")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["anchored"], 0);
}

#[tokio::test]
async fn user_routes_require_user_header() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // No X-User-UUID → 403.
    let resp = client
        .post(format!("http://{addr}/api/envelopes"))
        .json(&serde_json::json!({ "document_id": "nope", "title": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // With X-User-UUID → passes auth; 404 on nonexistent document proves it.
    let resp = client
        .post(format!("http://{addr}/api/envelopes"))
        .header("x-user-uuid", "11111111-1111-1111-1111-111111111111")
        .json(&serde_json::json!({ "document_id": "nope", "title": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
