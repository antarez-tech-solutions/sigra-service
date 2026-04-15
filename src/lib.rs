//! sigra-service — Core backend for the Sigra e-signature platform.
//!
//! Orchestrates document upload, signer management, signing workflows,
//! batch blockchain anchoring, and public verification.

pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod repo;
pub mod routes;
pub mod services;
pub mod state;

/// Service version.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
