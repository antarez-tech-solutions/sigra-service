//! Signer capability tokens — HMAC-SHA256, expiring, single-use.
//!
//! An HMAC is a *symmetric* authenticator: the same secret both mints and
//! verifies the tag, which is exactly right here — the service is both the
//! minter (at send time) and the verifier (at sign time). It is NOT
//! encryption: the payload is readable; the tag only proves the payload was
//! not forged or modified by someone lacking the secret.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::hmac;

use crate::error::ServiceError;

/// What a token asserts: "the bearer may act as this signer on this
/// envelope until exp".
pub struct SignerClaims {
    pub envelope_id: String,
    pub signer_id: String,
    pub exp_unix: i64,
}

fn payload(claims: &SignerClaims) -> String {
    format!("{}.{}.{}", claims.envelope_id, claims.signer_id, claims.exp_unix)
}

/// Mint a token. Only ever returned once, at send time.
pub fn mint(secret: &str, claims: &SignerClaims) -> String {
    let msg = payload(claims);
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, msg.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(msg.as_bytes()),
        URL_SAFE_NO_PAD.encode(tag.as_ref())
    )
}

/// Verify integrity + expiry and return the claims.
/// `ring::hmac::verify` recomputes the tag and compares in constant time.
pub fn verify(secret: &str, token: &str) -> Result<SignerClaims, ServiceError> {
    let invalid = || ServiceError::Unauthorized("invalid signer token".into());

    let (msg_b64, tag_b64) = token.split_once('.').ok_or_else(invalid)?;
    let msg = URL_SAFE_NO_PAD.decode(msg_b64).map_err(|_| invalid())?;
    let tag = URL_SAFE_NO_PAD.decode(tag_b64).map_err(|_| invalid())?;

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    hmac::verify(&key, &msg, &tag).map_err(|_| invalid())?;

    // Only parse AFTER the MAC checks out — never act on unauthenticated data.
    let msg = String::from_utf8(msg).map_err(|_| invalid())?;
    let parts: Vec<&str> = msg.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid());
    }
    let exp_unix: i64 = parts[2].parse().map_err(|_| invalid())?;
    if chrono::Utc::now().timestamp() > exp_unix {
        return Err(ServiceError::Unauthorized("signer token expired".into()));
    }

    Ok(SignerClaims {
        envelope_id: parts[0].to_string(),
        signer_id: parts[1].to_string(),
        exp_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> SignerClaims {
        SignerClaims {
            envelope_id: "env-1".into(),
            signer_id: "sig-1".into(),
            exp_unix: chrono::Utc::now().timestamp() + 60,
        }
    }

    #[test]
    fn roundtrip() {
        let t = mint("secret", &claims());
        let c = verify("secret", &t).unwrap();
        assert_eq!(c.envelope_id, "env-1");
        assert_eq!(c.signer_id, "sig-1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let t = mint("secret", &claims());
        let (_, tag) = t.split_once('.').unwrap();
        let forged_msg = URL_SAFE_NO_PAD.encode(b"env-1.sig-OTHER.9999999999");
        assert!(verify("secret", &format!("{forged_msg}.{tag}")).is_err());
    }

    #[test]
    fn wrong_secret_rejected() {
        let t = mint("secret", &claims());
        assert!(verify("other-secret", &t).is_err());
    }

    #[test]
    fn expired_rejected() {
        let mut c = claims();
        c.exp_unix = chrono::Utc::now().timestamp() - 1;
        let t = mint("secret", &c);
        assert!(verify("secret", &t).is_err());
    }

    #[test]
    fn malformed_rejected() {
        assert!(verify("secret", "no-dot").is_err());
        assert!(verify("secret", "not_base64!.also_not").is_err());
    }
}
