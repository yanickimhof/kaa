from kaa.collectors import arp, ssdp
from kaa.oui import Oui, is_multicast, is_randomized, normalize_mac

MACOS = """? (192.168.1.1) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]
? (192.168.1.20) at a4:83:e7:1:2:3 on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
"""

LINUX = """192.168.1.1 dev eth0 lladdr 00:1a:2b:3c:4d:5e REACHABLE
192.168.1.30 dev eth0 lladdr aa:bb:cc:dd:ee:ff STALE
192.168.1.40 dev eth0  FAILED
"""


def test_parse_macos_arp_normalises_and_filters():
    got = {n.ip: n.mac for n in arp.parse_arp(MACOS)}
    assert got == {"192.168.1.1": "00:1a:2b:3c:4d:5e", "192.168.1.20": "a4:83:e7:01:02:03"}


def test_parse_linux_neigh():
    got = {n.ip: n.mac for n in arp.parse_arp(LINUX)}
    assert got == {"192.168.1.1": "00:1a:2b:3c:4d:5e", "192.168.1.30": "aa:bb:cc:dd:ee:ff"}


def test_mac_helpers():
    assert normalize_mac("0-1A-2b-3-4-5") == "00:1a:2b:03:04:05"
    assert is_randomized("da:a1:19:00:00:01")
    assert not is_randomized("00:1a:2b:00:00:01")
    assert is_multicast("01:00:5e:00:00:fb")


def test_oui_lookup(tmp_path):
    f = tmp_path / "oui.csv"
    f.write_text("Registry,Assignment,Organization Name,Organization Address\n"
                 "MA-L,001A2B,Example Networks Inc,Somewhere\n")
    o = Oui(f)
    assert o.lookup("00:1a:2b:aa:bb:cc") == "Example Networks Inc"
    assert o.lookup("da:a1:19:00:00:01") is None  # randomised: never guess a vendor
    assert Oui(tmp_path / "missing.csv").loaded is False


def test_ssdp_parse():
    data = (b"HTTP/1.1 200 OK\r\nSERVER: Linux/5 UPnP/1.1 MiniUPnPd/2.2\r\n"
            b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nLOCATION: http://x/\r\n\r\n")
    h = ssdp.parse_response(data)
    assert h["server"].startswith("Linux") and "InternetGatewayDevice" in h["st"]


def test_valid_mac_rejects_placeholders():
    from kaa.oui import valid_mac
    assert valid_mac("a4:83:e7:aa:bb:cc") and valid_mac("0:1a:2b:3:4:5")
    for bad in (None, "", "02:00:00:00:00:00", "00:00:00:00:00:00", "self:en0", "a4:83"):
        assert not valid_mac(bad)


def test_sweep_counts_errors_by_name(monkeypatch):
    import errno, ipaddress
    from kaa.collectors import arp
    from kaa.scope import Scope

    class Sock:
        def setblocking(self, _): pass
        def close(self): pass
        def sendto(self, *_):
            raise OSError(errno.EHOSTUNREACH, "No route to host")

    monkeypatch.setattr(arp.socket, "socket", lambda *a, **k: Sock())
    scope = Scope([ipaddress.ip_network("192.168.7.0/24")], set(), set(), 1024)
    out = arp.sweep(scope, settle=0, limit=10)
    assert out == {"contacted": 10, "errors": {"EHOSTUNREACH": 10}}


def test_read_table_falls_back_to_system_python_when_arp_is_empty(monkeypatch):
    calls = []

    def fake_run(cmd):
        calls.append(cmd[0])
        return "? (192.168.1.5) at aa:bb:cc:dd:ee:01 on en0 [ethernet]" if cmd[0] == "/usr/bin/python3" else ""

    monkeypatch.setattr(arp, "_run", fake_run)
    monkeypatch.setattr(arp.shutil, "which", lambda c: "/x/" + c)
    monkeypatch.setattr(arp, "_system_python_available", lambda: True)
    assert [n.ip for n in arp.read_table()] == ["192.168.1.5"]
    assert calls[-1] == "/usr/bin/python3"


def _route_msg(ip: str, mac: bytes) -> bytes:
    import socket, struct
    dst = struct.pack("<BBH4s8x", 16, socket.AF_INET, 0, socket.inet_aton(ip))
    gw = struct.pack("<BBHBBBB", 20, 18, 4, 6, 0, 6, 0) + mac + bytes(6)  # sockaddr_dl
    body = dst + gw
    hdr = struct.pack("<HBBHxxiiiiiii", 92 + len(body), 5, 0x14, 4, 0x400, 3, 0, 0, 0, 0, 0)
    return hdr + bytes(92 - len(hdr)) + body


def test_route_dump_parser_decodes_neighbours():
    data = _route_msg("192.168.4.1", bytes.fromhex("74b6b69f51cd")) + \
        _route_msg("192.168.4.23", bytes.fromhex("70ee5091 04e0".replace(" ", "")))
    got = {n.ip: n.mac for n in arp._parse_route_dump(data)}
    assert got == {"192.168.4.1": "74:b6:b6:9f:51:cd", "192.168.4.23": "70:ee:50:91:04:e0"}
