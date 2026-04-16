use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerStatus {
    Pending,
    Signed,
    Declined,
    Expired,
}

/// A participant in a signing envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signer {
    #[serde(rename = "_id")]
    pub id: String,
    pub envelope_id: String,
    pub email: Option<String>,
    pub wallet_address: Option<String>,
    pub name: String,
    /// Position in signing order (1-based).
    pub order: i32,
    pub status: SignerStatus,
    pub signed_at: Option<DateTime<Utc>>,
    pub signature_data: Option<String>,
}
