//! Authentication extractors.
//!
//! Identity is a handler *parameter*, not a function handlers must remember
//! to call. Any handler that takes [`AuthenticatedUser`] cannot be reached
//! without the gateway enriching the request — the extractor runs before the
//! handler body and before body extraction. The infra (ingress → api-gateway)
//! authenticates the user and injects `X-User-UUID`; services trust it
//! unconditionally because the perimeter strips inbound copies of trust headers
//! before re-adding authenticated values.

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
        _st: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // The gateway has already authenticated the request and injected
        // `X-User-UUID`. The perimeter strips inbound trust headers before
        // re-adding authenticated values — we trust the header as-is.
        let uuid = header(parts, "x-user-uuid")
            .ok_or_else(|| ServiceError::Forbidden("missing X-User-UUID header".into()))?;
        Ok(AuthenticatedUser(uuid.to_string()))
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
