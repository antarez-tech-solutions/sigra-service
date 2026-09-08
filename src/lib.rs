//! sigra-service — Core backend for the Sigra e-signature platform.

pub mod auth;
pub mod binding;
pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod repo;
pub mod routes;
pub mod services;
pub mod state;
pub mod tokens;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use std::sync::Arc;

use axum::http::{header, HeaderValue, Method};
use axum::Router;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

/// Build the application router (used by `main` and integration tests).
pub async fn app() -> Result<Router, Box<dyn std::error::Error>> {
    let config = config::AppConfig::from_env();
    let db = db::connect(&config).await?;
    db::ensure_indexes(&db).await?;

    let s3_config = if config.s3_endpoint.is_some() {
        antarez_s3_storage::S3Config::minio(
            config.s3_bucket.clone(),
            config.s3_endpoint.clone().unwrap(),
        )
    } else {
        antarez_s3_storage::S3Config::aws(
            config.s3_bucket.clone(),
            config.s3_region.clone(),
        )
    };
    let s3 = Arc::new(antarez_s3_storage::S3Client::new(s3_config).await?);

    let st = state::AppState { db, s3, config };

    services::anchoring::spawn_anchor_loop(
        st.db.clone(),
        Arc::new(st.config.clone()),
        st.config.anchor_interval_secs,
    );

    let mut router = routes::router()
        .with_state(st)
        .layer(TraceLayer::new_for_http());

    // Dev-only CORS. Unset (the default) = no CORS layer at all: the gateway
    // is the single CORS authority in deployed environments.
    if let Ok(origins) = std::env::var("CORS_ALLOWED_ORIGINS") {
        let list: Vec<HeaderValue> = origins
            .split(',')
            .map(str::trim)
            .filter(|o| !o.is_empty())
            .map(|o| {
                if !o.starts_with("http://") && !o.starts_with("https://") {
                    return Err(format!("origin {o:?} must start with http:// or https://"));
                }
                if o.chars().any(|c| c.is_whitespace()) {
                    return Err(format!("origin {o:?} must not contain whitespace"));
                }
                o.parse::<HeaderValue>()
                    .map_err(|e| format!("origin {o:?} is not a valid header value: {e}"))
            })
            .collect::<Result<_, _>>()
            .map_err(|e| format!("invalid CORS_ALLOWED_ORIGINS: {e}"))?;
        if !list.is_empty() {
            router = router.layer(
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list(list))
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION]),
            );
        }
    }

    Ok(router)
}
