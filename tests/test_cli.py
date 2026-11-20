import socket

from kaa import cli


def test_port_busy_detects_listener_and_free_port():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert cli.port_busy("127.0.0.1", port)
        assert not cli.kaa_running(f"http://127.0.0.1:{port}")  # listener is not Kaa
    finally:
        srv.close()
    assert not cli.port_busy("127.0.0.1", port)


def test_serve_refuses_busy_port_without_starting_scanner(env, capsys):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    port = srv.getsockname()[1]
    try:
        assert cli.main(["serve", "--open", "--port", str(port)]) == 1
    finally:
        srv.close()
    assert "used by another program" in capsys.readouterr().err
