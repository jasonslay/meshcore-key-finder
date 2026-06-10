# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-10

### Added

- CLI to brute-force Ed25519 key pairs whose public key hex matches a chosen prefix.
- MeshCore-compatible key generation: `SHA-512(seed)` → clamped orlp private key, orlp-style base-point multiplication for the public key.
- `--validate` to check whether an existing MeshCore private key hex string would import successfully.
- `--workers` / `-j` for parallel search across CPU cores.
- `--json` for machine-readable output.
- `--allow-reserved` to permit keys whose public key starts with `00` or `FF` (reserved in MeshCore).
- Live progress reporting with attempt count, throughput, elapsed time, and ETA.
- Reserved-prefix rejection (`00` and `FF` first bytes) matching MeshCore firmware behavior.
- Unit tests against MeshCore firmware test vectors and real device samples.
- CI (format, clippy, tests, `cargo audit`) and local pre-commit hooks.

### Changed

- Rewrote the tool in Rust for higher throughput and native parallelism.
- Replaced `libsodium-sys` with pure-Rust `curve25519-dalek` for public key derivation, removing the system libsodium build dependency.

### Fixed

- MeshCore private key generation so generated keys import successfully on device firmware.

[0.1.0]: https://github.com/jasonslay/meshcore-key-finder/releases/tag/v0.1.0
