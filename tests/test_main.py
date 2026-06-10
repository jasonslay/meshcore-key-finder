import json
from unittest.mock import MagicMock, patch

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from main import (
    find_key_with_prefix,
    main,
    meshcore_private_key_hex,
    public_key_hex,
    validate_prefix,
)


@pytest.fixture
def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def test_public_key_hex_format(private_key: Ed25519PrivateKey) -> None:
    public_hex = public_key_hex(private_key)

    assert len(public_hex) == 64
    assert public_hex == public_hex.upper()
    assert all(c in "0123456789ABCDEF" for c in public_hex)


def test_meshcore_private_key_hex_format(private_key: Ed25519PrivateKey) -> None:
    private_hex = meshcore_private_key_hex(private_key)
    public_hex = public_key_hex(private_key)

    assert len(private_hex) == 128
    assert private_hex == private_hex.lower()
    assert private_hex.endswith(public_hex.lower())
    assert all(c in "0123456789abcdef" for c in private_hex)


def test_find_key_with_prefix_matches(private_key: Ed25519PrivateKey) -> None:
    prefix = public_key_hex(private_key)[:2]

    with patch(
        "main.Ed25519PrivateKey.generate",
        side_effect=[Ed25519PrivateKey.generate(), private_key],
    ):
        found_key, attempts = find_key_with_prefix(
            prefix,
            progress_interval=999,
        )

    assert attempts == 2
    assert public_key_hex(found_key).startswith(prefix)


@patch("main.public_key_hex")
@patch("main.Ed25519PrivateKey.generate")
def test_find_key_with_prefix_skips_reserved(
    mock_generate: MagicMock,
    mock_public_key_hex: MagicMock,
) -> None:
    reserved_key = MagicMock()
    valid_key = MagicMock()
    mock_generate.side_effect = [reserved_key, valid_key]
    mock_public_key_hex.side_effect = [
        "00ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "0AABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
    ]

    found_key, attempts = find_key_with_prefix("0", progress_interval=999)

    assert attempts == 2
    assert found_key is valid_key


@patch("main.public_key_hex")
@patch("main.Ed25519PrivateKey.generate")
def test_find_key_with_prefix_allows_reserved_when_disabled(
    mock_generate: MagicMock,
    mock_public_key_hex: MagicMock,
) -> None:
    reserved_key = MagicMock()
    mock_generate.return_value = reserved_key
    mock_public_key_hex.return_value = (
        "00ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567"
    )

    found_key, attempts = find_key_with_prefix(
        "00",
        avoid_reserved=False,
        progress_interval=999,
    )

    assert attempts == 1
    assert found_key is reserved_key


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("beef", "BEEF"),
        ("Ab12", "AB12"),
    ],
)
def test_validate_prefix_accepts_valid_hex(value: str, expected: str) -> None:
    ctx = click.Context(click.Command("test"))

    assert validate_prefix(ctx, None, value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "GHIJ", "be ef", "0xBEEF"],
)
def test_validate_prefix_rejects_invalid_hex(value: str) -> None:
    ctx = click.Context(click.Command("test"))

    with pytest.raises(click.BadParameter, match="hexadecimal"):
        validate_prefix(ctx, None, value)


def test_validate_prefix_rejects_too_long_prefix() -> None:
    ctx = click.Context(click.Command("test"))

    with pytest.raises(click.BadParameter, match="64-character"):
        validate_prefix(ctx, None, "A" * 65)


@patch("main.find_key_with_prefix")
def test_cli_plain_output(mock_find: MagicMock, private_key: Ed25519PrivateKey) -> None:
    mock_find.return_value = (private_key, 42)
    runner = CliRunner()

    result = runner.invoke(main, ["AA"])

    assert result.exit_code == 0
    assert "Searching for public key prefix: AA" in result.stderr
    assert "Found after 42 attempts" in result.stderr
    assert f"Public key:  {public_key_hex(private_key)}" in result.stdout
    assert f"Private key: {meshcore_private_key_hex(private_key)}" in result.stdout


@patch("main.find_key_with_prefix")
def test_cli_json_output(mock_find: MagicMock, private_key: Ed25519PrivateKey) -> None:
    mock_find.return_value = (private_key, 42)
    runner = CliRunner()

    result = runner.invoke(main, ["aa", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["prefix"] == "AA"
    assert data["public_key"] == public_key_hex(private_key)
    assert data["private_key"] == meshcore_private_key_hex(private_key)
    assert data["attempts"] == 42
    assert "elapsed_seconds" in data


@patch("main.find_key_with_prefix")
def test_cli_passes_allow_reserved(mock_find: MagicMock) -> None:
    mock_find.return_value = (Ed25519PrivateKey.generate(), 1)
    runner = CliRunner()

    result = runner.invoke(main, ["00", "--allow-reserved"])

    assert result.exit_code == 0
    mock_find.assert_called_once_with("00", avoid_reserved=False)


def test_cli_rejects_invalid_prefix() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["NOTHEX"])

    assert result.exit_code != 0
    assert (
        "hexadecimal" in result.stderr.lower() or "hexadecimal" in result.output.lower()
    )
