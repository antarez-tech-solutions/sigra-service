use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::post,
    Json, Router,
};
use serde::Deserialize;

use crate::auth::{ct_eq, AuthenticatedUser};
use crate::error::ServiceError;
use crate::models::*;
use crate::repo::{EnvelopeRepo, SignerRepo};
use crate::state::AppState;
use crate::tokens::{mint, verify, SignerClaims};

#[derive(Deserialize)]
struct SendReq {
    #[allow(dead_code)]
    message: Option<String>,
}

#[derive(Deserialize)]
struct SignReq {
    signer_id: String,
    signature_data: String,
}

/// POST /api/envelopes/:id/send — transition Draft → Pending.
async fn send_envelope(
    State(st): State<AppState>,
    AuthenticatedUser(owner): AuthenticatedUser,
    Path(id): Path<String>,
    Json(_body): Json<SendReq>,
) -> Result<Json<serde_json::Value>, ServiceError> {
    let env = EnvelopeRepo::find_by_id(&st.db, &id).await?;
    if env.owner_id != owner {
        return Err(ServiceError::Forbidden("not your envelope".into()));
    }
    if env.status != EnvelopeStatus::Draft {
        return Err(ServiceError::BadRequest("only draft envelopes can be sent".into()));
    }

    let signers = SignerRepo::find_by_envelope(&st.db, &id).await?;
    if signers.is_empty() {
        return Err(ServiceError::BadRequest("add at least one signer first".into()));
    }

    EnvelopeRepo::update_status(&st.db, &id, &EnvelopeStatus::Pending).await?;

    // Mint one single-use capability token per signer. We store only its
    // SHA-256 hash (a DB leak yields hashes, not usable tokens) and return
    // the plaintext tokens once. Out-of-band delivery (email) is a later
    // concern; for now the owner forwards them.
    let exp_unix = chrono::Utc::now().timestamp() + st.config.signer_token_ttl_secs as i64;
    let mut signing_tokens = serde_json::Map::new();
    for s in &signers {
        let token = mint(
            &st.config.signer_token_secret,
            &SignerClaims {
                envelope_id: id.clone(),
                signer_id: s.id.clone(),
                exp_unix,
            },
        );
        SignerRepo::set_token_hash(&st.db, &s.id, &sigrachain_crypto::hash_string(&token)).await?;
        signing_tokens.insert(s.id.clone(), serde_json::Value::String(token));
    }
    tracing::info!(id = %id, signers = signers.len(), "envelope sent");

    Ok(Json(serde_json::json!({
        "id": id, "status": "pending", "signers": signers.len(),
        "signing_tokens": signing_tokens,
    })))
}

/// POST /api/envelopes/:id/sign — record one signer's signature.
async fn sign_envelope(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SignReq>,
) -> Result<Json<serde_json::Value>, ServiceError> {
    // Authenticate the signer BEFORE any DB read: a valid capability token
    // is the credential (the signer is not a platform user, so no gateway
    // identity applies here).
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ServiceError::Unauthorized("missing signer token".into()))?;
    let claims = verify(&st.config.signer_token_secret, token)?;
    if claims.envelope_id != id || claims.signer_id != body.signer_id {
        return Err(ServiceError::Forbidden("token does not match this signer".into()));
    }

    let env = EnvelopeRepo::find_by_id(&st.db, &id).await?;
    if env.status != EnvelopeStatus::Pending {
        return Err(ServiceError::BadRequest("envelope not pending".into()));
    }

    let signer = SignerRepo::find_by_id(&st.db, &body.signer_id).await?;
    if signer.envelope_id != id {
        return Err(ServiceError::BadRequest("signer not in this envelope".into()));
    }
    if signer.status != SignerStatus::Pending {
        return Err(ServiceError::BadRequest("signer already acted".into()));
    }

    // Bind the presented token to the one minted for this signer at send
    // time (constant-time compare of SHA-256 hashes). Stops a token minted
    // for a different signer/envelope that happens to share a secret.
    let stored = signer
        .token_hash
        .as_deref()
        .ok_or_else(|| ServiceError::Unauthorized("no active token for signer".into()))?;
    if !ct_eq(stored, &sigrachain_crypto::hash_string(token)) {
        return Err(ServiceError::Unauthorized("token has been superseded".into()));
    }

    let signers = SignerRepo::find_by_envelope(&st.db, &id).await?;
    if env.signing_order == SigningOrder::Sequential {
        check_turn(&signer, &signers)?;
    }

    SignerRepo::update_signed(&st.db, &body.signer_id, &body.signature_data).await?;
    tracing::info!(signer = %body.signer_id, envelope = %id, "signed");

    let all_signed = signers
        .iter()
        .all(|s| s.id == body.signer_id || s.status == SignerStatus::Signed);

    if all_signed {
        EnvelopeRepo::update_status(&st.db, &id, &EnvelopeStatus::Completed).await?;
        tracing::info!(envelope = %id, "all signed — completed");
    }

    Ok(Json(serde_json::json!({
        "signer_id": body.signer_id,
        "status": "signed",
        "envelope_completed": all_signed,
    })))
}

/// For sequential flow, verify all prior signers have signed.
fn check_turn(current: &Signer, all: &[Signer]) -> Result<(), ServiceError> {
    for s in all {
        if s.order < current.order && s.status != SignerStatus::Signed {
            return Err(ServiceError::BadRequest(format!(
                "signer {} (order {}) must sign first",
                s.name, s.order
            )));
        }
    }
    Ok(())
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/envelopes/{id}/send", post(send_envelope))
        .route("/api/envelopes/{id}/sign", post(sign_envelope))
}
