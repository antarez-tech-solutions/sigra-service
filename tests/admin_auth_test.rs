//! Auth integration tests: the /admin/anchor guard and the gateway secret.
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
        std::env::set_var("GATEWAY_SHARED_SECRET", "test-gateway-secret");
        std::env::set_var("ADMIN_TOKEN", "test-admin-token");
    }

    let app = sigra_service::app().await.expect("build app");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn admin_anchor_requires_token() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // No token → 401.
    let resp = client
        .post(format!("http://{addr}/admin/anchor"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong token → 401.
    let resp = client
        .post(format!("http://{addr}/admin/anchor"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Correct token → 200. With no completed envelopes, anchor_batch
    // returns 0 without touching the chain (services/anchoring.rs).
    let resp = client
        .post(format!("http://{addr}/admin/anchor"))
        .bearer_auth("test-admin-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["anchored"], 0);
}

#[tokio::test]
async fn user_routes_require_gateway_secret() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    // X-User-UUID alone is NOT an identity: without the gateway secret the
    // header must be ignored (this is the anti-spoofing property).
    let resp = client
        .post(format!("http://{addr}/api/envelopes"))
        .header("x-user-uuid", "11111111-1111-1111-1111-111111111111")
        .json(&serde_json::json!({ "document_id": "nope", "title": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Wrong gateway secret → still forbidden.
    let resp = client
        .post(format!("http://{addr}/api/envelopes"))
        .header("x-gateway-auth", "not-the-secret")
        .header("x-user-uuid", "11111111-1111-1111-1111-111111111111")
        .json(&serde_json::json!({ "document_id": "nope", "title": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Correct secret + identity → auth passes; this request then 404s on
    // the nonexistent document, proving we got past the extractor.
    let resp = client
        .post(format!("http://{addr}/api/envelopes"))
        .header("x-gateway-auth", "test-gateway-secret")
        .header("x-user-uuid", "11111111-1111-1111-1111-111111111111")
        .json(&serde_json::json!({ "document_id": "nope", "title": "t" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
