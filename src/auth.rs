//! Authentication extractors.
//!
//! Identity is a handler *parameter*, not a function handlers must remember
//! to call. Any handler that takes [`AuthenticatedUser`] cannot be reached
//! without passing the gateway checks — the extractor runs before the
//! handler body and before body extraction.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ServiceError;
use crate::state::AppState;

/// Constant-time string equality. Use for ALL comparisons against secrets:
/// a naive `==` returns at the first differing byte, leaking match length
/// through timing. XOR-fold over every byte — same pattern as the crypto
/// engine's proof comparison (sigrachain-crypto-engine proof/verifier.rs).
/// Length is compared eagerly; only the content comparison is secret.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn header<'a>(parts: &'a Parts, name: &str) -> Option<&'a str> {
    parts.headers.get(name).and_then(|v| v.to_str().ok())
}

/// The platform user, as authenticated by the private gateway.
///
/// Destructure in handlers: `AuthenticatedUser(owner): AuthenticatedUser`.
pub struct AuthenticatedUser(pub String);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        st: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // 1. Prove the request came through the gateway. Without this, any
        //    client that can reach the service directly could mint an
        //    identity by setting X-User-UUID itself.
        let presented = header(parts, "x-gateway-auth")
            .ok_or_else(|| ServiceError::Forbidden("missing gateway auth".into()))?;
        if !ct_eq(presented, &st.config.gateway_shared_secret) {
            return Err(ServiceError::Forbidden("invalid gateway auth".into()));
        }
        // 2. Only then trust the identity header the gateway injected.
        let uuid = header(parts, "x-user-uuid")
            .ok_or_else(|| ServiceError::Forbidden("missing X-User-UUID header".into()))?;
        Ok(AuthenticatedUser(uuid.to_string()))
    }
}

/// Guard for operator-only routes (`Authorization: Bearer <ADMIN_TOKEN>`).
pub struct AdminAuth;

impl FromRequestParts<AppState> for AdminAuth {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        st: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let bearer = header(parts, "authorization")
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or_else(|| ServiceError::Unauthorized("missing admin token".into()))?;
        if !ct_eq(bearer, &st.config.admin_token) {
            return Err(ServiceError::Unauthorized("invalid admin token".into()));
        }
        Ok(AdminAuth)
    }
}

#[cfg(test)]
mod tests {
    use super::ct_eq;

    #[test]
    fn ct_eq_semantics() {
        assert!(ct_eq("same-secret", "same-secret"));
        assert!(!ct_eq("same-secret", "same-secreT"));
        assert!(!ct_eq("short", "longer-value"));
        assert!(!ct_eq("", "x"));
        assert!(ct_eq("", ""));
    }
}
