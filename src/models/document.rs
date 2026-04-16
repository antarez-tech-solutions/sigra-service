use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A hashed and stored document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Document {
    #[serde(rename = "_id")]
    pub id: String,
    /// Owner's user UUID (from X-User-UUID header).
    pub owner_id: String,
    pub filename: String,
    pub content_type: String,
    pub size_bytes: i64,
    /// SHA-256 hash of the raw bytes.
    pub hash: String,
    /// S3 object key.
    pub s3_key: String,
    pub created_at: DateTime<Utc>,
}
