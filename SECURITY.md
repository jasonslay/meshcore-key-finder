# Security Policy

## Supported Versions

Security fixes are applied to the latest release on the `main` branch.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1.0 | No |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in this project, please report it privately rather than opening a public issue.

**Email:** [jason@jtslay.com](mailto:jason@jtslay.com)

Include as much detail as you can:

- A description of the issue and its potential impact
- Steps to reproduce, or a proof of concept if available
- The version or commit you tested against

You can expect an initial response within a few business days. I will work with you to understand and address valid reports before any public disclosure.

You may also use [GitHub private vulnerability reporting](https://github.com/jasonslay/meshcore-key-finder/security/advisories/new) if that is enabled on the repository.

## What Counts as a Security Issue

Reports are welcome for problems such as:

- Incorrect key derivation that produces keys incompatible with MeshCore firmware
- Validation logic that accepts malformed or unsafe private keys
- Memory safety bugs, use-after-free, or other undefined behavior in release builds
- Dependency vulnerabilities with a plausible exploit path in this tool

The following are generally **out of scope**:

- Brute-force search taking a long time for long prefixes (expected behavior)
- Vanity prefix collisions with other nodes on the mesh (operational risk, not a software defect)
- Loss or exposure of a private key due to user error (printing, sharing, committing to git, etc.)

## Handling Private Keys

This tool generates cryptographic secrets. Treat the private key like a password:

- Do not share it or commit it to version control.
- Store it only on your MeshCore device or in a secure backup.
- Anyone with the private key can impersonate your node on the mesh.

The tool writes progress to stderr and prints the key pair to stdout when a match is found. Be mindful of shell history, terminal scrollback, log aggregation, and screen sharing when running searches.

## Dependency Audits

CI runs `cargo audit` on every push and pull request. Dependency updates are reviewed before merging.
