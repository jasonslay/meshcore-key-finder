# meshcore-key-finder

[![CI](https://github.com/jasonslay/meshcore-key-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/jasonslay/meshcore-key-finder/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/jasonslay/meshcore-key-finder)](LICENSE)
[![Release](https://img.shields.io/github/v/release/jasonslay/meshcore-key-finder)](https://github.com/jasonslay/meshcore-key-finder/releases)

Generate Ed25519 key pairs for [MeshCore](https://github.com/ripplebiz/MeshCore) nodes whose public key starts with a chosen hexadecimal prefix.

> **Disclaimer:** This is an independent, community-maintained tool. It is not affiliated with, endorsed by, or maintained by the [MeshCore](https://github.com/ripplebiz/MeshCore) project or its authors. "MeshCore" is used only to describe compatibility with that project's key format and firmware behavior.

MeshCore uses the first byte of a node's public key as its short node identifier in routing and advertisements. Choosing a distinctive prefix helps you pick a memorable ID and reduces collisions with nearby nodes.

This tool brute-forces random Ed25519 keys until the hex-encoded public key matches your desired prefix, then prints the key pair in MeshCore's expected format.

Written in Rust for fast native Ed25519 key generation and efficient parallel search across CPU cores. Release builds with LTO and `target-cpu=native` maximize throughput on your hardware.

## Requirements

- [Rust](https://www.rust-lang.org/tools/install) 1.85 or newer (stable)

## Installation

```bash
git clone https://github.com/jasonslay/meshcore-key-finder.git
cd meshcore-key-finder
cargo build --release
```

The binary is installed to `target/release/meshcore-key-finder`.

## Usage

```bash
cargo run --release -- [PREFIX] [OPTIONS]
# or
./target/release/meshcore-key-finder [PREFIX] [OPTIONS]
```

`PREFIX` is the optional hex prefix for the public key. Omit it to generate a random key pair. Alternatively, pass `--validate` with a private key hex string to check whether it would import into MeshCore (no prefix search).

### Examples

```bash
# Generate a random key pair (no vanity prefix)
cargo run --release

# Find a key with a custom prefix
cargo run --release -- F8A1

# Use 8 worker threads
cargo run --release -- BEEF --workers 8

# Output as JSON
cargo run --release -- CAFE --json

# Allow reserved MeshCore prefixes (see below)
cargo run --release -- 00AB --allow-reserved

# Check whether an existing private key would import into MeshCore
cargo run --release -- --validate 50278930f6e01e4a008127ab7ed0745032fbe716d628d81f39c1db644b911e4dc9b24c3ab070d62875f3b561f7ec0a1f59bd7b7f72091666f39e68d01ad5c529
```

### Options

| Option | Description |
| --- | --- |
| `PREFIX` | Hex prefix to match (0–64 characters). Case-insensitive. Omit to generate any key pair, or use `--validate` instead of searching. |
| `--validate` | Check whether a MeshCore private key hex string (128 lowercase hex characters) would import successfully; prints the derived public key. |
| `--workers`, `-j` | Number of worker threads (default: logical CPU count). |
| `--json` | Print the result as JSON instead of plain text. |
| `--allow-reserved` | Allow keys whose public key starts with `00` or `FF`. |
| `--help` | Show usage information. |

Progress (attempt count, total and per-worker rate, elapsed time, and live ETA) is written to stderr while searching. Press Ctrl+C to stop gracefully.

## Output format

The search loop generates keys the same way MeshCore firmware does: `SHA-512(seed)` → clamped scalar `||` `RH`, then derives the public key with orlp-style base-point multiplication (not standard RFC 8032 seed export). Each result is validated against MeshCore's firmware import checks before output.

| Field | Size | Encoding |
| --- | --- | --- |
| Public key | 32 bytes | 64 uppercase hex characters |
| Private key | 64 bytes (orlp expanded key: clamped scalar `a` + `RH` from SHA-512(seed)) | 128 lowercase hex characters |

Example plain-text output:

```
Public key:  BEEFD4C232F948A0376163421BEEEB21ABFF5262FE5F33496A61B930EDB2C7C4
Private key: 50278930f6e01e4a008127ab7ed0745032fbe716d628d81f39c1db644b911e4dc9b24c3ab070d62875f3b561f7ec0a1f59bd7b7f72091666f39e68d01ad5c529
```

Example JSON output:

```json
{
  "public_key": "BEEFD4C232F948A0376163421BEEEB21ABFF5262FE5F33496A61B930EDB2C7C4",
  "private_key": "50278930f6e01e4a008127ab7ed0745032fbe716d628d81f39c1db644b911e4dc9b24c3ab070d62875f3b561f7ec0a1f59bd7b7f72091666f39e68d01ad5c529",
  "prefix": "BEEF",
  "attempts": 112128,
  "elapsed_seconds": 0.17,
  "workers": 16,
  "attempts_per_second": 656085.0,
  "attempts_per_second_per_worker": 41005.0
}
```

## Reserved prefixes

By default, this tool **rejects** keys whose public key begins with `00` or `FF` (the first byte is `0x00` or `0xFF`).

MeshCore reserves these values in the protocol:

- **`0x00`** — Used for broadcast and wildcard addressing. A node whose ID byte is `0x00` can collide with special routing semantics rather than behaving as a normal unique node identifier.
- **`0xFF`** — Also reserved for special protocol purposes in the mesh firmware and routing layer.

MeshCore firmware itself skips generating identities with these prefixes when creating new node IDs. This tool follows the same rule so the keys it produces are safe to import onto a MeshCore device without conflicting with reserved protocol addresses.

If you explicitly want a key starting with `00` or `FF` (for testing or other non-standard use), pass `--allow-reserved`.

**Note:** A prefix like `BEEF` is not reserved — only the first *byte* matters for reservation. `BEEF` starts with `0xBE`, which is fine. A prefix of `00AB` would match reserved keys unless you pass `--allow-reserved`.

## Search time

Search time grows exponentially with prefix length. Each additional hex character multiplies the expected number of attempts by roughly 16.

When you start a search, the tool prints the expected average attempts for your prefix (slightly higher when reserved `00`/`FF` keys are skipped). While searching, progress updates include an **ETA** based on your measured rate:

```
Searching for public key prefix: BEEF (16 workers)
Estimate: 66,052 average attempts (4 hex chars)
Attempts: 32,768  Rate: 640,000/s total (~40,000/s per worker)  Elapsed: 0.05s  ETA: 0.05s
```

| Prefix length | Approx. average attempts |
| --- | --- |
| 1 char (`B`) | ~16 |
| 2 chars (`BE`) | ~256 |
| 4 chars (`BEEF`) | ~65,536 (~66k with reserved skip) |
| 6 chars (`BEEF00`) | ~16.7 million |
| 8 chars (`BEEF00FF`) | ~4.3 billion |
| 10 chars (`BEEF00FF00`) | ~1.1 trillion |

## Performance

The search loop targets a simple hot path: generate a key, check the prefix, repeat. Key optimizations:

- **Raw-byte prefix matching** — `PrefixMatcher` pre-parses hex nibbles once and compares against the 32-byte public key directly (no per-attempt hex string allocation).
- **Native parallelism** — one OS thread per worker with per-thread RNG and attempt counters.
- **Batched polling** — workers check the stop/interrupt flag every 64 attempts instead of on every keygen.
- **Release tuning** — link-time optimization, single codegen unit, and `target-cpu=native` (via `.cargo/config.toml`) so the binary uses your CPU's best instructions.

By default, worker count matches your **logical** CPU count (including hyperthreads). This workload is embarrassingly parallel; using all logical CPUs often yields higher total throughput than physical cores alone.

```bash
cargo build --release
./target/release/meshcore-key-finder BEEF        # uses all logical CPUs
./target/release/meshcore-key-finder BEEF -j 8   # limit workers
```

Typical throughput on a modern desktop with 16 logical CPUs and a release build is ~400–650k/s total (~25–40k/s per worker). A 4-character prefix like `BEEF` usually finishes in well under a second; 8-character prefixes can take hours at ~400k/s.

## Development

The crate is split into focused modules under `src/`:

| Module | Role |
| --- | --- |
| `prefix` | Hex validation and `PrefixMatcher` (nibble comparison on raw key bytes) |
| `search` | Single- and multi-threaded keygen loop, progress reporting, Ctrl+C handling |
| `estimate` | Average-attempt math, ETA formatting, comma-separated number display |
| `keys` | MeshCore orlp private key export, public key hex, import validation |

Git hooks run the same checks as CI before each commit. Install [lefthook](https://github.com/evilmartians/lefthook), then enable hooks in this repo:

```bash
lefthook install
```

Run checks manually:

```bash
cargo test
cargo clippy --all-targets -- -D warnings
cargo audit
cargo fmt --all
```

## Security

The generated private key is a secret. Treat it like a password:

- Do not share it or commit it to version control.
- Store it only on the MeshCore device or in a secure backup.
- Anyone with the private key can impersonate your node on the mesh.

To report a vulnerability in this tool, see [SECURITY.md](SECURITY.md).

## Acknowledgments

This project was built with assistance from AI coding tools ([Cursor](https://cursor.com)).
All code was written, reviewed, and tested by the maintainer before release.

## License

MIT License. See [LICENSE](LICENSE).
