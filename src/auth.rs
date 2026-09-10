//! Authentication extractors.
//!
//! Identity is a handler *parameter*, not a function handlers must remember
//! to call. Any handler that takes [`AuthenticatedUser`] cannot be reached
//! without an authenticated request: the extractor runs before the handler
//! body and before body extraction. The platform's edge authenticates the
//! user and injects `X-User-UUID`; this service safely trusts that header.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::error::ServiceError;
use crate::state::AppState;

/// Constant-time string equality. Use for ALL comparisons against secrets:
/// a naive `==` returns at the first differing byte, leaking match length
/// through timing. XOR-fold over every byte instead.
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

/// The platform user, as authenticated by the platform's edge.
///
/// Destructure in handlers: `AuthenticatedUser(owner): AuthenticatedUser`.
pub struct AuthenticatedUser(pub String);

impl FromRequestParts<AppState> for AuthenticatedUser {
    type Rejection = ServiceError;

    async fn from_request_parts(
        parts: &mut Parts,
        _st: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // The edge has already authenticated the request and injected
        // `X-User-UUID`; we safely trust the header.
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
