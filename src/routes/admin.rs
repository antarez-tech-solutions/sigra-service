//! Operator-only routes. Never exposed through the public gateway —
//! cluster-internal access only.

use axum::{extract::State, routing::post, Json, Router};

use crate::auth::AuthenticatedUser;
use crate::error::ServiceError;
use crate::services::anchoring::anchor_batch;
use crate::state::AppState;

/// POST /admin/anchor — manually trigger one anchor batch.
///
/// Submits a real EAS attestation transaction when completed envelopes
/// exist.
async fn trigger_anchor(
    _user: AuthenticatedUser,
    State(st): State<AppState>,
) -> Result<Json<serde_json::Value>, ServiceError> {
    let n = anchor_batch(&st.db, &st.config).await?;
    Ok(Json(serde_json::json!({ "anchored": n })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/admin/anchor", post(trigger_anchor))
}
