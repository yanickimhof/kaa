"""Internet health: latency, jitter, loss, and a short speed test. Outbound only."""

from __future__ import annotations

import socket
import statistics
import time
import urllib.request

DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
UP_URL = "https://speed.cloudflare.com/__up"
TARGETS = (("1.1.1.1", 443), ("9.9.9.9", 443))


def reachable(timeout: float = 2.0) -> bool:
    """True when at least one well known public endpoint accepts a TCP connection."""
    for host, port in TARGETS:
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def ping(timeout: float = 2.0) -> float | None:
    """Milliseconds to open a TCP connection to a well known public endpoint, None if unreachable."""
    for host, port in TARGETS:
        t = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return round((time.perf_counter() - t) * 1000, 1)
        except OSError:
            continue
    return None


def latency(samples: int = 10, timeout: float = 2.0) -> dict:
    host, port = TARGETS[0]
    times: list[float] = []
    lost = 0
    for _ in range(samples):
        t = time.perf_counter()
        try:
            with socket.create_connection((host, port), timeout=timeout):
                times.append((time.perf_counter() - t) * 1000)
        except OSError:
            lost += 1
        time.sleep(0.1)
    if not times:
        return {"latency": None, "jitter": None, "loss": 1.0}
    jitter = statistics.mean(abs(a - b) for a, b in zip(times, times[1:])) if len(times) > 1 else 0.0
    return {"latency": round(statistics.median(times), 1), "jitter": round(jitter, 1),
            "loss": round(lost / samples, 2)}


def download(ctx, seconds: float = 6.0, nbytes: int = 40_000_000) -> float | None:
    """Megabits per second, reading for at most ``seconds``."""
    try:
        req = urllib.request.Request(DOWN_URL.format(n=nbytes), headers={"User-Agent": "kaa"})
        got, t0 = 0, time.perf_counter()
        with urllib.request.urlopen(req, timeout=10, context=ctx) as r:  # noqa: S310
            while time.perf_counter() - t0 < seconds:
                chunk = r.read(262144)
                if not chunk:
                    break
                got += len(chunk)
        dt = time.perf_counter() - t0
        return round(got * 8 / dt / 1e6, 1) if got and dt > 0 else None
    except (OSError, ValueError):
        return None


def upload(ctx, nbytes: int = 8_000_000) -> float | None:
    try:
        data = bytes(nbytes)
        req = urllib.request.Request(UP_URL, data=data, method="POST",
                                     headers={"User-Agent": "kaa", "Content-Type": "application/octet-stream"})
        t0 = time.perf_counter()
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:  # noqa: S310
            r.read()
        dt = time.perf_counter() - t0
        return round(nbytes * 8 / dt / 1e6, 1) if dt > 0 else None
    except (OSError, ValueError):
        return None


def run(ctx, progress=None) -> dict:
    """Latency, download, upload. ``progress(phase)`` is called before each step."""
    step = progress or (lambda _p: None)
    step("latency")
    out = latency()
    step("download")
    out["down"] = download(ctx) if out["latency"] is not None else None
    step("upload")
    out["up"] = upload(ctx) if out["down"] is not None else None
    return out
