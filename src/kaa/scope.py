"""Scope guard. Kaa only ever touches networks you own.

Every active probe goes through ``Scope.require``. Public ranges are refused
at construction time, not at probe time.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterator

import psutil

SKIP_IFACE_PREFIXES = (
    "lo", "utun", "awdl", "llw", "gif", "stf", "anpi", "ap", "bridge",
    "docker", "br-", "veth", "vmnet", "vboxnet", "tun", "tap", "wg",
)


class ScopeError(ValueError):
    pass


def is_lan_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(ip.is_private and not ip.is_loopback and not ip.is_link_local)


@dataclass(frozen=True)
class LocalInterface:
    name: str
    ip: str
    network: ipaddress.IPv4Network
    mac: str | None


def local_interfaces() -> list[LocalInterface]:
    out: list[LocalInterface] = []
    stats = psutil.net_if_stats()
    for name, addrs in psutil.net_if_addrs().items():
        if name.startswith(SKIP_IFACE_PREFIXES):
            continue
        if name in stats and not stats[name].isup:
            continue
        mac = None
        for a in addrs:
            if a.family == psutil.AF_LINK:
                mac = a.address.lower().replace("-", ":")
        for a in addrs:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            try:
                iface = ipaddress.ip_interface(f"{a.address}/{a.netmask}")
            except ValueError:
                continue
            if is_lan_address(iface.ip):
                out.append(LocalInterface(name, str(iface.ip), iface.network, mac))
    return out


class Scope:
    def __init__(self, networks: list[ipaddress.IPv4Network], own_ips: set[str],
                 exclude: set[str], max_hosts: int):
        self.networks = networks
        self.own_ips = own_ips
        self.exclude = exclude
        self.max_hosts = max_hosts

    def contains(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in self.networks)

    def allowed(self, ip: str) -> bool:
        return self.contains(ip) and ip.lower() not in self.exclude

    def require(self, ip: str) -> None:
        if not self.contains(ip):
            raise ScopeError(f"{ip} is outside the configured scope")
        if ip.lower() in self.exclude:
            raise ScopeError(f"{ip} is excluded")

    def hosts(self) -> Iterator[str]:
        for net in self.networks:
            for h in net.hosts():
                s = str(h)
                if s not in self.own_ips and s not in self.exclude:
                    yield s

    def describe(self) -> list[str]:
        return [str(n) for n in self.networks]


def build_scope(configured: list[str], max_hosts: int = 1024,
                exclude: list[str] | None = None) -> Scope:
    interfaces = local_interfaces()
    own = {i.ip for i in interfaces}
    nets: list[ipaddress.IPv4Network] = []
    if configured:
        for raw in configured:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError as exc:
                raise ScopeError(f"invalid network {raw!r}") from exc
            if not isinstance(net, ipaddress.IPv4Network):
                raise ScopeError("only IPv4 networks are supported in 0.1")
            if not net.is_private or net.is_loopback or net.is_link_local:
                raise ScopeError(f"{raw} is not a private network; refused")
            nets.append(net)
    else:
        nets = [i.network for i in interfaces]
    if not nets:
        raise ScopeError("no private network found; are you connected?")
    total = sum(n.num_addresses for n in nets)
    if total > max_hosts + 2 * len(nets):
        raise ScopeError(
            f"scope has {total} addresses, above max_hosts={max_hosts}; "
            "narrow scan.networks in config.toml"
        )
    return Scope(nets, own, {e.lower() for e in (exclude or [])}, max_hosts)
