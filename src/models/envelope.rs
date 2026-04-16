use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Draft,
    Pending,
    Completed,
    Anchored,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningOrder {
    Parallel,
    Sequential,
}

/// A signing envelope — one document, one or more signers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(rename = "_id")]
    pub id: String,
    pub document_id: String,
    pub owner_id: String,
    pub title: String,
    pub status: EnvelopeStatus,
    pub signing_order: SigningOrder,
    pub deadline: Option<DateTime<Utc>>,
    pub attestation_uid: Option<String>,
    pub merkle_root: Option<String>,
    pub merkle_proof: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
