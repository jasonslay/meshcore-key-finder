import json
import multiprocessing as mp
import os
import queue
import struct
import sys
import time
from multiprocessing import shared_memory

import click
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

RESERVED_PREFIXES = ("00", "ff")
INTERRUPTED_EXIT_CODE = 130
PROGRESS_BATCH = 1000
_COUNTER_FORMAT = "Q"
_COUNTER_SIZE = struct.calcsize(_COUNTER_FORMAT)


class SearchInterrupted(Exception):
    def __init__(self, attempts: int, elapsed: float) -> None:
        self.attempts = attempts
        self.elapsed = elapsed
        super().__init__(attempts, elapsed)


class SharedSearchState:
    def __init__(self, workers: int) -> None:
        self.workers = workers
        self.shm = shared_memory.SharedMemory(
            create=True,
            size=workers * _COUNTER_SIZE + 1,
        )
        self._reset()

    def _reset(self) -> None:
        for worker_id in range(self.workers):
            self.set_attempts(worker_id, 0)
        self._buffer[-1] = 0

    @property
    def _buffer(self) -> memoryview:
        return self.shm.buf

    @property
    def name(self) -> str:
        return self.shm.name

    def stop_is_set(self) -> bool:
        return self._buffer[-1] != 0

    def set_stop(self) -> None:
        self._buffer[-1] = 1

    def set_attempts(self, worker_id: int, attempts: int) -> None:
        struct.pack_into(
            _COUNTER_FORMAT, self._buffer, worker_id * _COUNTER_SIZE, attempts
        )

    def get_attempts(self, worker_id: int) -> int:
        return struct.unpack_from(
            _COUNTER_FORMAT, self._buffer, worker_id * _COUNTER_SIZE
        )[0]

    def total_attempts(self) -> int:
        return sum(self.get_attempts(worker_id) for worker_id in range(self.workers))

    def close(self) -> None:
        self.shm.close()
        self.shm.unlink()


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


def private_key_seed(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def matches_prefix(public_hex: str, prefix: str, *, avoid_reserved: bool) -> bool:
    if not public_hex.startswith(prefix):
        return False
    return not (avoid_reserved and public_hex[:2].lower() in RESERVED_PREFIXES)


def format_rate(attempts: int, elapsed: float, workers: int) -> str:
    if elapsed <= 0 or attempts == 0:
        return "0/s"

    total_rate = attempts / elapsed
    if workers <= 1:
        return f"{total_rate:,.0f}/s"

    per_worker = total_rate / workers
    return f"{total_rate:,.0f}/s total (~{per_worker:,.0f}/s per worker)"


def rate_stats(attempts: int, elapsed: float, workers: int) -> dict[str, float]:
    if elapsed <= 0:
        return {
            "attempts_per_second": 0.0,
            "attempts_per_second_per_worker": 0.0,
        }

    total_rate = attempts / elapsed
    return {
        "attempts_per_second": round(total_rate, 3),
        "attempts_per_second_per_worker": round(total_rate / workers, 3),
    }


def report_progress(
    attempts: int,
    started: float,
    last_report: float,
    *,
    interval: float,
    workers: int,
) -> float:
    now = time.monotonic()
    if now - last_report < interval:
        return last_report

    elapsed = now - started
    print(
        f"\rAttempts: {attempts:,}  "
        f"Rate: {format_rate(attempts, elapsed, workers)}  "
        f"Elapsed: {elapsed:.1f}s",
        end="",
        file=sys.stderr,
    )
    return now


def _worker_search(
    prefix: str,
    avoid_reserved: bool,
    worker_id: int,
    shm_name: str,
    workers: int,
    result_queue: mp.queues.Queue[bytes],
) -> None:
    shm = shared_memory.SharedMemory(name=shm_name)
    buffer = shm.buf
    counter_offset = worker_id * _COUNTER_SIZE
    local_attempts = 0

    try:
        while buffer[-1] == 0:
            local_attempts += 1
            if local_attempts % PROGRESS_BATCH == 0:
                struct.pack_into(
                    _COUNTER_FORMAT, buffer, counter_offset, local_attempts
                )

            private_key = Ed25519PrivateKey.generate()
            public_hex = public_key_hex(private_key)

            if matches_prefix(public_hex, prefix, avoid_reserved=avoid_reserved):
                struct.pack_into(
                    _COUNTER_FORMAT, buffer, counter_offset, local_attempts
                )
                buffer[-1] = 1
                result_queue.put(private_key_seed(private_key), block=False)
                return
    finally:
        struct.pack_into(_COUNTER_FORMAT, buffer, counter_offset, local_attempts)
        shm.close()


def get_mp_context() -> mp.context.BaseContext:
    if sys.platform == "linux":
        return mp.get_context("fork")
    return mp.get_context("spawn")


def _terminate_processes(processes: list[mp.Process]) -> None:
    for process in processes:
        if process.is_alive():
            process.terminate()
    for process in processes:
        process.join(timeout=1)


def find_key_with_prefix(
    prefix: str,
    *,
    avoid_reserved: bool = True,
    progress_interval: float = 1.0,
    workers: int = 1,
) -> tuple[Ed25519PrivateKey, int]:
    prefix = prefix.upper()
    if workers <= 1:
        return _find_key_single(
            prefix,
            avoid_reserved=avoid_reserved,
            progress_interval=progress_interval,
            workers=workers,
        )
    return _find_key_multiprocess(
        prefix,
        avoid_reserved=avoid_reserved,
        progress_interval=progress_interval,
        workers=workers,
    )


def _find_key_single(
    prefix: str,
    *,
    avoid_reserved: bool,
    progress_interval: float,
    workers: int,
) -> tuple[Ed25519PrivateKey, int]:
    attempts = 0
    started = time.monotonic()
    last_report = started

    try:
        while True:
            attempts += 1
            private_key = Ed25519PrivateKey.generate()
            public_hex = public_key_hex(private_key)

            if matches_prefix(public_hex, prefix, avoid_reserved=avoid_reserved):
                return private_key, attempts

            last_report = report_progress(
                attempts,
                started,
                last_report,
                interval=progress_interval,
                workers=workers,
            )
    except KeyboardInterrupt as exc:
        raise SearchInterrupted(attempts, time.monotonic() - started) from exc


def _find_key_multiprocess(
    prefix: str,
    *,
    avoid_reserved: bool,
    progress_interval: float,
    workers: int,
) -> tuple[Ed25519PrivateKey, int]:
    ctx = get_mp_context()
    state = SharedSearchState(workers)
    result_queue = ctx.Queue(maxsize=1)
    processes: list[mp.Process] = []
    started = time.monotonic()
    last_report = started

    try:
        for worker_id in range(workers):
            process = ctx.Process(
                target=_worker_search,
                args=(
                    prefix,
                    avoid_reserved,
                    worker_id,
                    state.name,
                    workers,
                    result_queue,
                ),
            )
            process.start()
            processes.append(process)

        while True:
            try:
                seed = result_queue.get(timeout=0.1)
            except queue.Empty:
                last_report = report_progress(
                    state.total_attempts(),
                    started,
                    last_report,
                    interval=progress_interval,
                    workers=workers,
                )
                continue

            state.set_stop()
            _terminate_processes(processes)
            return load_private_key(seed), state.total_attempts()
    except KeyboardInterrupt as exc:
        state.set_stop()
        _terminate_processes(processes)
        elapsed = time.monotonic() - started
        raise SearchInterrupted(state.total_attempts(), elapsed) from exc
    finally:
        state.close()


def resolve_worker_count(workers: int | None) -> int:
    if workers is None:
        return os.cpu_count() or 1
    return workers


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
    callback=validate_prefix,
)
@click.option(
    "--workers",
    "-j",
    "workers",
    type=click.IntRange(1),
    default=None,
    help="Number of worker processes (default: CPU count).",
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
def main(
    prefix: str,
    workers: int | None,
    allow_reserved: bool,
    as_json: bool,
) -> None:
    """Generate Ed25519 keys whose public key hex starts with a prefix."""
    worker_count = resolve_worker_count(workers)
    click.echo(
        f"Searching for public key prefix: {prefix} "
        f"({worker_count} worker{'s' if worker_count != 1 else ''})",
        err=True,
    )

    started = time.monotonic()
    try:
        private_key, attempts = find_key_with_prefix(
            prefix,
            avoid_reserved=not allow_reserved,
            workers=worker_count,
        )
    except SearchInterrupted as exc:
        click.echo(err=True)
        click.echo(
            f"Interrupted after {exc.attempts:,} attempts in {exc.elapsed:.2f}s "
            f"({format_rate(exc.attempts, exc.elapsed, worker_count)})",
            err=True,
        )
        raise SystemExit(INTERRUPTED_EXIT_CODE) from None

    elapsed = time.monotonic() - started

    public_hex = public_key_hex(private_key)
    private_hex = meshcore_private_key_hex(private_key)

    click.echo(err=True)
    click.echo(
        f"Found after {attempts:,} attempts in {elapsed:.2f}s "
        f"({format_rate(attempts, elapsed, worker_count)})",
        err=True,
    )

    result = {
        "public_key": public_hex,
        "private_key": private_hex,
        "prefix": prefix,
        "attempts": attempts,
        "elapsed_seconds": round(elapsed, 3),
        "workers": worker_count,
        **rate_stats(attempts, elapsed, worker_count),
    }

    if as_json:
        click.echo(json.dumps(result, indent=2))
    else:
        click.echo(f"Public key:  {public_hex}")
        click.echo(f"Private key: {private_hex}")


if __name__ == "__main__":
    main()
