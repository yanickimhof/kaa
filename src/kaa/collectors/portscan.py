"""Opt-in TCP connect scan of a short list of risky or telling ports.

Connect only: no raw packets, no payloads, no banner grabbing beyond the TCP
handshake. Every target is checked against the scope guard first.
"""

from __future__ import annotations

import asyncio

from ..scope import Scope


async def _probe(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> int | None:
    async with sem:
        try:
            _r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        except (OSError, asyncio.TimeoutError):
            return None
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        return port


async def _scan(scope: Scope, ips: list[str], ports: list[int], timeout: float,
                concurrency: int) -> dict[str, list[int]]:
    sem = asyncio.Semaphore(concurrency)
    tasks: dict[str, list[asyncio.Task]] = {}
    for ip in ips:
        scope.require(ip)
        tasks[ip] = [asyncio.create_task(_probe(ip, p, timeout, sem)) for p in ports]
    out: dict[str, list[int]] = {}
    for ip, ts in tasks.items():
        res = await asyncio.gather(*ts)
        out[ip] = sorted(p for p in res if p is not None)
    return out


def scan(scope: Scope, ips: list[str], ports: list[int], timeout: float = 0.7,
         concurrency: int = 150) -> dict[str, list[int]]:
    return asyncio.run(_scan(scope, ips, ports, timeout, concurrency))
