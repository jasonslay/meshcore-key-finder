# meshcore-key-finder

Generate Ed25519 key pairs for [MeshCore](https://github.com/ripplebiz/MeshCore) nodes whose public key starts with a chosen hexadecimal prefix.

MeshCore uses the first byte of a node's public key as its short node identifier in routing and advertisements. Choosing a distinctive prefix helps you pick a memorable ID and reduces collisions with nearby nodes.

This tool brute-forces random Ed25519 keys until the hex-encoded public key matches your desired prefix, then prints the key pair in MeshCore's expected format.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/)

## Installation

```bash
git clone <repo-url>
cd meshcore-key-finder
uv sync
```

## Usage

```bash
uv run python main.py [PREFIX] [OPTIONS]
```

`PREFIX` is the required hex prefix for the public key.

### Examples

```bash
# Find a key with a custom prefix
uv run python main.py F8A1

# Use 8 worker processes
uv run python main.py BEEF --workers 8

# Output as JSON
uv run python main.py CAFE --json

# Allow reserved MeshCore prefixes (see below)
uv run python main.py 00AB --allow-reserved
```

### Options

| Option | Description |
| --- | --- |
| `PREFIX` | Hex prefix to match (1–64 characters). Case-insensitive. |
| `--workers`, `-j` | Number of worker processes (default: CPU count). |
| `--json` | Print the result as JSON instead of plain text. |
| `--allow-reserved` | Allow keys whose public key starts with `00` or `FF`. |
| `--help` | Show usage information. |

Progress (attempt count, rate, elapsed time) is written to stderr while searching.

## Output format

Keys follow the MeshCore identity format:

| Field | Size | Encoding |
| --- | --- | --- |
| Public key | 32 bytes | 64 uppercase hex characters |
| Private key | 64 bytes (32-byte seed + 32-byte public key) | 128 lowercase hex characters |

Example plain-text output:

```
Public key:  BEEF553747579B52F3DD2ACB0712CFD899D9681EBE72D467DAD209D2337D752C
Private key: 9f8c7c8c515be0b702fc131c5714c6508aa44356169b4cbe7022bfe4b18d0f0cbeef553747579b52f3dd2acb0712cfd899d9681ebe72d467dad209d2337d752c
```

Example JSON output:

```json
{
  "public_key": "BEEF553747579B52F3DD2ACB0712CFD899D9681EBE72D467DAD209D2337D752C",
  "private_key": "9f8c7c8c515be0b702fc131c5714c6508aa44356169b4cbe7022bfe4b18d0f0cbeef553747579b52f3dd2acb0712cfd899d9681ebe72d467dad209d2337d752c",
  "prefix": "BEEF",
  "attempts": 41412,
  "elapsed_seconds": 1.726
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

| Prefix length | Approx. average attempts |
| --- | --- |
| 2 chars (`BE`) | ~256 |
| 4 chars (`BEEF`) | ~65,536 |
| 6 chars (`BEEF00`) | ~16.7 million |
| 8 chars (`BEEF00FF`) | ~4.3 billion |

On a typical desktop CPU you can expect on the order of 20,000–30,000 attempts per second per worker. The search uses multiprocessing (not threads) so CPU-bound key generation can run in parallel across cores. Use `--workers` to control how many processes are used. A 4-character prefix usually completes in a few seconds; longer prefixes can take minutes to hours.

## Security

The generated private key is a secret. Treat it like a password:

- Do not share it or commit it to version control.
- Store it only on the MeshCore device or in a secure backup.
- Anyone with the private key can impersonate your node on the mesh.

## License

MIT License. See [LICENSE](LICENSE).
