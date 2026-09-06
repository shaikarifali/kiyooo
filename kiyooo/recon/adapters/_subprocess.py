"""Shared subprocess runner for adapters that shell out to a Go binary.

Not a `ToolAdapter` itself — a private helper the subprocess-backed adapters
call from their `run()`. Kills the child on cancellation (the orchestrator's
per-tool `asyncio.wait_for` cancels this coroutine on timeout; without an
explicit kill here, the child process would keep running as an orphan after
its Python awaiter gave up on it).
"""

from __future__ import annotations

import asyncio


async def run_subprocess(
    argv: list[str], *, stdin: bytes | None = None, env: dict[str, str] | None = None
) -> tuple[int, bytes, bytes]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE if stdin is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        stdout, stderr = await proc.communicate(stdin)
    except asyncio.CancelledError:
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, stdout, stderr
