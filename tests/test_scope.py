import pytest

from kaa.scope import ScopeError, build_scope


def test_private_network_accepted():
    s = build_scope(["192.168.10.0/24"])
    assert s.contains("192.168.10.7")
    assert not s.contains("192.168.11.7")
    assert "192.168.10.1" in set(s.hosts())


@pytest.mark.parametrize("net", ["8.8.8.0/24", "1.1.1.1/32", "127.0.0.0/8", "169.254.0.0/16"])
def test_public_or_special_refused(net):
    with pytest.raises(ScopeError):
        build_scope([net])


def test_too_large_refused():
    with pytest.raises(ScopeError):
        build_scope(["10.0.0.0/8"], max_hosts=1024)


def test_require_blocks_outside_and_excluded():
    s = build_scope(["192.168.10.0/24"], exclude=["192.168.10.50"])
    s.require("192.168.10.5")
    with pytest.raises(ScopeError):
        s.require("203.0.113.9")
    with pytest.raises(ScopeError):
        s.require("192.168.10.50")
    assert "192.168.10.50" not in set(s.hosts())


def test_invalid_network():
    with pytest.raises(ScopeError):
        build_scope(["not-a-network"])
