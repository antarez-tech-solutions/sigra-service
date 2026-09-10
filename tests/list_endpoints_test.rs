//! Integration tests for the document and envelope list endpoints.
//! GET /api/documents and GET /api/envelopes must return exactly the
//! authenticated caller's rows and never another owner's.
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
        // The local MinIO test instance uses static root credentials;
        // the AWS SDK credential chain reads these env vars.
        std::env::set_var("AWS_ACCESS_KEY_ID", "sigra-test");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "sigra-test-secret");
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    }

    let app = sigra_service::app().await.expect("build app");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

#[tokio::test]
async fn list_endpoints_scoped_to_caller() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let base = format!("http://{addr}");
    // Unique per-run owners so reruns never collide with leftover rows.
    let owner_a = uuid::Uuid::new_v4().to_string();
    let owner_b = uuid::Uuid::new_v4().to_string();

    // Both lists start empty for a fresh owner.
    let docs: serde_json::Value = client
        .get(format!("{base}/api/documents"))
        .header("x-user-uuid", &owner_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(docs, serde_json::json!([]));
    let envs: serde_json::Value = client
        .get(format!("{base}/api/envelopes"))
        .header("x-user-uuid", &owner_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(envs, serde_json::json!([]));

    // Create one document (A) and one envelope (A).
    let boundary = "testboundary123";
    let body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--{boundary}--\r\n"
    );
    let doc: serde_json::Value = client
        .post(format!("{base}/api/documents"))
        .header("x-user-uuid", &owner_a)
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(body)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let doc_id = doc["id"].as_str().expect("document id").to_string();

    let env: serde_json::Value = client
        .post(format!("{base}/api/envelopes"))
        .header("x-user-uuid", &owner_a)
        .json(&serde_json::json!({ "document_id": doc_id, "title": "t" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(env["id"].is_string());

    // Owner A now sees exactly one row in each list.
    let docs: serde_json::Value = client
        .get(format!("{base}/api/documents"))
        .header("x-user-uuid", &owner_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(docs.as_array().unwrap().len(), 1);
    let envs: serde_json::Value = client
        .get(format!("{base}/api/envelopes"))
        .header("x-user-uuid", &owner_a)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(envs.as_array().unwrap().len(), 1);

    // Owner B sees nothing of A's.
    let docs: serde_json::Value = client
        .get(format!("{base}/api/documents"))
        .header("x-user-uuid", &owner_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(docs, serde_json::json!([]));
    let envs: serde_json::Value = client
        .get(format!("{base}/api/envelopes"))
        .header("x-user-uuid", &owner_b)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(envs, serde_json::json!([]));

    // No header at all → 403 (the extractor, not the list logic).
    let resp = client
        .get(format!("{base}/api/documents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
