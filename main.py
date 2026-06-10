import json
import sys
import time

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RESERVED_PREFIXES = ("00", "ff")


def public_key_hex(private_key: Ed25519PrivateKey) -> str:
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return public_bytes.hex().upper()


def meshcore_private_key_hex(private_key: Ed25519PrivateKey) -> str:
    seed = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (seed + public_bytes).hex().lower()


def find_key_with_prefix(
    prefix: str,
    *,
    avoid_reserved: bool = True,
    progress_interval: float = 1.0,
) -> tuple[Ed25519PrivateKey, int]:
    prefix = prefix.upper()
    attempts = 0
    started = time.monotonic()
    last_report = started

    while True:
        attempts += 1
        private_key = Ed25519PrivateKey.generate()
        public_hex = public_key_hex(private_key)

        if public_hex.startswith(prefix):
            if avoid_reserved and public_hex[:2].lower() in RESERVED_PREFIXES:
                continue
            return private_key, attempts

        now = time.monotonic()
        if now - last_report >= progress_interval:
            elapsed = now - started
            rate = attempts / elapsed if elapsed > 0 else 0.0
            print(
                f"\rAttempts: {attempts:,}  "
                f"Rate: {rate:,.0f}/s  "
                f"Elapsed: {elapsed:.1f}s",
                end="",
                file=sys.stderr,
            )
            last_report = now


def validate_prefix(_ctx: click.Context, _param: click.Parameter, value: str) -> str:
    prefix = value.upper()
    if not prefix or not all(c in "0123456789ABCDEF" for c in prefix):
        raise click.BadParameter("must be non-empty hexadecimal characters")
    if len(prefix) > 64:
        raise click.BadParameter("cannot be longer than a 64-character public key")
    return prefix


@click.command()
@click.argument(
    "prefix",
    default="BEEF",
    callback=validate_prefix,
)
@click.option(
    "--allow-reserved",
    is_flag=True,
    help="Allow prefixes starting with 00 or FF (reserved in MeshCore).",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Print the result as JSON.",
)
def main(prefix: str, allow_reserved: bool, as_json: bool) -> None:
    """Generate Ed25519 keys whose public key hex starts with a prefix."""
    click.echo(f"Searching for public key prefix: {prefix}", err=True)

    started = time.monotonic()
    private_key, attempts = find_key_with_prefix(
        prefix,
        avoid_reserved=not allow_reserved,
    )
    elapsed = time.monotonic() - started

    public_hex = public_key_hex(private_key)
    private_hex = meshcore_private_key_hex(private_key)

    click.echo(err=True)
    click.echo(
        f"Found after {attempts:,} attempts in {elapsed:.2f}s "
        f"({attempts / elapsed:,.0f}/s)",
        err=True,
    )

    result = {
        "public_key": public_hex,
        "private_key": private_hex,
        "prefix": prefix,
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 3),
    }

    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"Public key:  {public_hex}")
        click.echo(f"Private key: {private_hex}")


if __name__ == "__main__":
    main()
