use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let app = axum::Router::new()
        .route("/health", axum::routing::get(|| async { "ok" }));

    let addr = "0.0.0.0:8080";
    tracing::info!("sigra-service listening on {addr}");

    let listener = TcpListener::bind(addr).await.expect("failed to bind");
    axum::serve(listener, app).await.expect("server error");
}
