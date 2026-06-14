//! Operator-only routes. Never exposed through the public gateway —
//! cluster-internal access only (deployment guard in Phase 6).

use axum::{extract::State, routing::post, Json, Router};

use crate::auth::AdminAuth;
use crate::error::ServiceError;
use crate::services::anchoring::anchor_batch;
use crate::state::AppState;

/// POST /admin/anchor — manually trigger one anchor batch.
///
/// Submits a real EAS attestation transaction when completed envelopes
/// exist, so this MUST stay behind AdminAuth: anonymous access would let
/// anyone spend gas from the attester account.
async fn trigger_anchor(
    _admin: AdminAuth,
    State(st): State<AppState>,
) -> Result<Json<serde_json::Value>, ServiceError> {
    let n = anchor_batch(&st.db, &st.config).await?;
    Ok(Json(serde_json::json!({ "anchored": n })))
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/admin/anchor", post(trigger_anchor))
}
