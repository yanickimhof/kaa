"""Neighbour discovery from the operating system's ARP table.

The optional sweep sends one empty UDP datagram per host in scope. That is
enough to make the OS resolve the address (and fill its ARP table) without
needing root and without any scanning payload.
"""

from __future__ import annotations

import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass

from ..oui import is_multicast, normalize_mac
from ..scope import Scope

ARP_BSD = re.compile(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]+)")
NEIGH_LINUX = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s.*?lladdr\s+([0-9a-fA-F:]+)", re.M)


@dataclass(frozen=True)
class Neighbour:
    ip: str
    mac: str


def parse_arp(text: str) -> list[Neighbour]:
    out: dict[str, Neighbour] = {}
    for ip, mac in ARP_BSD.findall(text):
        out[ip] = Neighbour(ip, normalize_mac(mac))
    for ip, mac in NEIGH_LINUX.findall(text):
        out[ip] = Neighbour(ip, normalize_mac(mac))
    return [n for n in out.values()
            if not is_multicast(n.mac) and n.mac != "00:00:00:00:00:00"]


def read_table() -> list[Neighbour]:
    for cmd in (["arp", "-an"], ["ip", "neigh", "show"]):
        if shutil.which(cmd[0]):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                continue
            found = parse_arp(res.stdout)
            if found:
                return found
    return []


def sweep(scope: Scope, settle: float = 1.5) -> int:
    """Nudge the OS to resolve every host in scope. Returns hosts contacted."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    count = 0
    try:
        for ip in scope.hosts():
            scope.require(ip)
            try:
                sock.sendto(b"", (ip, 9))
            except OSError:
                pass
            count += 1
            if count % 64 == 0:
                time.sleep(0.05)
    finally:
        sock.close()
    time.sleep(settle)
    return count


def default_gateway() -> str | None:
    for cmd, pat in ((["route", "-n", "get", "default"], r"gateway:\s*(\S+)"),
                     (["ip", "route", "show", "default"], r"default via (\S+)")):
        if not shutil.which(cmd[0]):
            continue
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = re.search(pat, res.stdout)
        if m and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", m.group(1)):
            return m.group(1)
    return None


def reverse_dns(ips: list[str], per_host: float = 2.0) -> dict[str, str]:
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as FTimeout

    def one(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except OSError:
            return None

    out: dict[str, str] = {}
    pool = ThreadPoolExecutor(max_workers=16)
    futures = {ip: pool.submit(one, ip) for ip in ips}
    for ip, fut in futures.items():
        try:
            name = fut.result(timeout=per_host)
        except FTimeout:
            name = None
        if name:
            out[ip] = name
    pool.shutdown(wait=False, cancel_futures=True)
    return out
