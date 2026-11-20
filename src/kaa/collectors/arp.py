"""Neighbour discovery from the operating system's ARP table.

The optional sweep sends one empty UDP datagram per host in scope. That is
enough to make the OS resolve the address (and fill its ARP table) without
needing root and without any scanning payload.
"""

from __future__ import annotations

import ctypes
import errno
import itertools
import re
import shutil
import socket
import struct
import subprocess
import sys
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


# macOS hands an empty ARP table to `arp` when it is started by a non Apple Python
# (the uv managed interpreter), although the same command works from Terminal or
# from Apple's own Python. The relay below runs `arp` under /usr/bin/python3.
_RELAY = ("import subprocess,sys;"
          "sys.stdout.write(subprocess.run(['/usr/sbin/arp','-an'],"
          "capture_output=True,text=True,timeout=10).stdout)")


def _system_python_available() -> bool:
    if sys.platform != "darwin" or not shutil.which("/usr/bin/python3"):
        return False
    # Without the developer tools /usr/bin/python3 is a stub that opens an installer.
    try:
        return subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True,
                              timeout=5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


_RTM_HDR = 92  # sizeof(struct rt_msghdr) on 64 bit macOS


def _parse_route_dump(data: bytes) -> list[Neighbour]:
    """Decode the BSD routing socket dump of the IPv4 neighbour (ARP) table."""
    out: list[Neighbour] = []
    off = 0
    while off + _RTM_HDR <= len(data):
        (msglen,) = struct.unpack_from("<H", data, off)
        if msglen < _RTM_HDR or off + msglen > len(data):
            break
        (addrs,) = struct.unpack_from("<i", data, off + 12)
        p, sas = off + _RTM_HDR, []
        for bit in range(8):
            if not addrs & (1 << bit):
                sas.append(None)
                continue
            salen = data[p]
            sas.append(data[p:p + salen])
            p += (1 + ((salen - 1) | 3)) if salen else 4
        dst, gw = sas[0], sas[1]
        if dst and gw and len(dst) >= 8 and dst[1] == socket.AF_INET \
                and len(gw) >= 8 and gw[1] == 18 and gw[6] == 6:  # AF_LINK, 6 byte address
            start = 8 + gw[5]
            mac = ":".join(f"{b:02x}" for b in gw[start:start + 6])
            out.append(Neighbour(socket.inet_ntoa(bytes(dst[4:8])), normalize_mac(mac)))
        off += msglen
    return [n for n in out if not is_multicast(n.mac) and n.mac != "00:00:00:00:00:00"]


def read_sysctl() -> list[Neighbour]:
    """Read the ARP table in process, without starting the `arp` command."""
    if sys.platform != "darwin":
        return []
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        mib = (ctypes.c_int * 6)(4, 17, 0, socket.AF_INET, 2, 0x400)  # NET_RT_FLAGS, RTF_LLINFO
        size = ctypes.c_size_t(0)
        if libc.sysctl(mib, 6, None, ctypes.byref(size), None, 0) != 0:
            return []
        buf = ctypes.create_string_buffer(size.value + 8192)
        size = ctypes.c_size_t(len(buf))
        if libc.sysctl(mib, 6, buf, ctypes.byref(size), None, 0) != 0:
            return []
        return _parse_route_dump(buf.raw[:size.value])
    except (OSError, ValueError, struct.error, IndexError):
        return []


def methods() -> dict[str, int]:
    """How many neighbours each reading method returns (for `kaa doctor`)."""
    found = {"arp command": len(parse_arp(_run(["arp", "-an"]))),
             "sysctl": len(read_sysctl())}
    if _system_python_available():
        found["system python relay"] = len(parse_arp(_run(["/usr/bin/python3", "-c", _RELAY])))
    return found


def read_table() -> list[Neighbour]:
    for cmd in (["arp", "-an"], ["ip", "neigh", "show"]):
        if shutil.which(cmd[0]):
            found = parse_arp(_run(cmd))
            if found:
                return found
    found = read_sysctl()
    if found:
        return found
    if _system_python_available():
        return parse_arp(_run(["/usr/bin/python3", "-c", _RELAY]))
    return []


def _send(sock: socket.socket, ip: str, errors: dict[str, int]) -> None:
    try:
        sock.sendto(b"", (ip, 9))
    except OSError as exc:
        name = errno.errorcode.get(exc.errno or 0, str(exc.errno))
        errors[name] = errors.get(name, 0) + 1


def sweep(scope: Scope, settle: float = 1.5, limit: int | None = None) -> dict:
    """Nudge the OS to resolve hosts in scope.

    Returns {"contacted": n, "errors": {errno name: count}}. A pile of
    EHOSTUNREACH or EPERM errors usually means macOS is blocking Local Network
    access for this process.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    count = 0
    errors: dict[str, int] = {}
    try:
        hosts = scope.hosts() if limit is None else itertools.islice(scope.hosts(), limit)
        for ip in hosts:
            scope.require(ip)
            _send(sock, ip, errors)
            count += 1
            if count % 64 == 0:
                time.sleep(0.05)
    finally:
        sock.close()
    time.sleep(settle)
    return {"contacted": count, "errors": errors}


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
