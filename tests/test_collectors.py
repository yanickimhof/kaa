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
