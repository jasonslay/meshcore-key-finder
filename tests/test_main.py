import json
import os
import queue
from unittest.mock import ANY, MagicMock, patch

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from main import (
    INTERRUPTED_EXIT_CODE,
    SearchInterrupted,
    find_key_with_prefix,
    format_rate,
    main,
    matches_prefix,
    meshcore_private_key_hex,
    public_key_hex,
    rate_stats,
    resolve_worker_count,
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


def test_matches_prefix_skips_reserved() -> None:
    assert not matches_prefix(
        "00ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "00",
        avoid_reserved=True,
    )
    assert matches_prefix(
        "00ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF01234567",
        "00",
        avoid_reserved=False,
    )


def test_resolve_worker_count_defaults_to_cpu_count() -> None:
    assert resolve_worker_count(None) == (os.cpu_count() or 1)


def test_resolve_worker_count_uses_explicit_value() -> None:
    assert resolve_worker_count(4) == 4


def test_format_rate_single_worker() -> None:
    assert format_rate(10_000, 2.0, 1) == "5,000/s"


def test_format_rate_multi_worker() -> None:
    assert format_rate(80_000, 2.0, 4) == "40,000/s total (~10,000/s per worker)"


def test_rate_stats() -> None:
    assert rate_stats(80_000, 2.0, 4) == {
        "attempts_per_second": 40_000.0,
        "attempts_per_second_per_worker": 10_000.0,
    }


def test_find_key_with_prefix_multiprocess(private_key: Ed25519PrivateKey) -> None:
    prefix = public_key_hex(private_key)[:1]

    found_key, attempts = find_key_with_prefix(
        prefix,
        workers=2,
        progress_interval=999,
    )

    assert attempts >= 1
    assert public_key_hex(found_key).startswith(prefix)


def test_find_key_with_prefix_single_interrupt() -> None:
    with (
        patch(
            "main.Ed25519PrivateKey.generate",
            side_effect=KeyboardInterrupt,
        ),
        pytest.raises(SearchInterrupted) as exc_info,
    ):
        find_key_with_prefix("AA", progress_interval=999)

    assert exc_info.value.attempts == 1
    assert exc_info.value.elapsed >= 0


@patch("main._terminate_processes")
@patch("main.report_progress", side_effect=KeyboardInterrupt)
@patch("main.mp.get_context")
def test_find_key_with_prefix_multiprocess_interrupt(
    mock_get_context: MagicMock,
    mock_report_progress: MagicMock,
    mock_terminate: MagicMock,
) -> None:
    mock_ctx = MagicMock()
    mock_get_context.return_value = mock_ctx
    mock_queue = MagicMock()
    mock_queue.get.side_effect = queue.Empty
    mock_ctx.Queue.return_value = mock_queue
    mock_process = MagicMock()
    mock_ctx.Process.return_value = mock_process

    with pytest.raises(SearchInterrupted):
        find_key_with_prefix("FFFF", workers=2, progress_interval=0.01)

    mock_terminate.assert_called_once()


def test_find_key_with_prefix_matches(private_key: Ed25519PrivateKey) -> None:
    prefix = public_key_hex(private_key)[:2]
    decoy_key = Ed25519PrivateKey.generate()

    with patch(
        "main.Ed25519PrivateKey.generate",
        side_effect=[decoy_key, private_key],
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
    assert "workers" in data
    assert "attempts_per_second" in data
    assert "attempts_per_second_per_worker" in data


@patch("main.find_key_with_prefix")
def test_cli_passes_workers(
    mock_find: MagicMock,
    private_key: Ed25519PrivateKey,
) -> None:
    mock_find.return_value = (private_key, 1)
    runner = CliRunner()

    result = runner.invoke(main, ["AA", "--workers", "4"])

    assert result.exit_code == 0
    assert "4 workers" in result.stderr
    mock_find.assert_called_once_with("AA", avoid_reserved=True, workers=4)


@patch("main.find_key_with_prefix")
def test_cli_handles_interrupt(mock_find: MagicMock) -> None:
    mock_find.side_effect = SearchInterrupted(12_345, 3.5)
    runner = CliRunner()

    result = runner.invoke(main, ["AA", "--workers", "4"])

    assert result.exit_code == INTERRUPTED_EXIT_CODE
    assert (
        "Interrupted after 12,345 attempts in 3.50s (3,527/s total "
        "(~882/s per worker))" in result.stderr
    )


@patch("main.find_key_with_prefix")
def test_cli_passes_allow_reserved(mock_find: MagicMock) -> None:
    mock_find.return_value = (Ed25519PrivateKey.generate(), 1)
    runner = CliRunner()

    result = runner.invoke(main, ["00", "--allow-reserved"])

    assert result.exit_code == 0
    mock_find.assert_called_once_with("00", avoid_reserved=False, workers=ANY)


def test_cli_rejects_invalid_prefix() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["NOTHEX"])

    assert result.exit_code != 0
    assert (
        "hexadecimal" in result.stderr.lower() or "hexadecimal" in result.output.lower()
    )
