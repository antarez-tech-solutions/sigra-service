# sigra-service

The core backend service for the Sigra e-signature platform — document upload, signer management, signing workflow, blockchain anchoring, and public verification.

Built with Rust (Axum), orchestrating the Sigra foundation libraries: `sigrachain-crypto-engine` for hashing and Merkle proofs, `antarez-eas-client` for on-chain attestations via EAS on Arbitrum, and `antarez-s3-storage` for encrypted document storage.

## Status

**Not yet implemented.** This repo reserves the project structure.

## Planned Features

- Document upload and encrypted S3 storage
- Signer management (email and wallet-based)
- Signing workflow orchestration (sequential and parallel)
- SHA-256 document hashing via crypto engine
- Batch anchoring — Merkle tree root submission to EAS on Arbitrum
- Public verification API — verify document authenticity by hash or tx ID
- Pre-signed URL generation for direct client uploads/downloads
- Audit trail and proof certificate generation

## Architecture

```
sigra-service (Axum)
├── sigrachain-crypto-engine  — hashing, Merkle trees, proofs
├── antarez-eas-client        — EAS attestations on Arbitrum
└── antarez-s3-storage        — S3/MinIO object storage
```

## License

This repository and all contributions are licensed under the [LGPL 3.0](https://www.gnu.org/licenses/lgpl-3.0.html), unless otherwise specified in subdirectory LICENSE files.
