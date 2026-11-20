"""Light, read-only checks run during a deep check, only on ports already found open.

No password is ever tried (a wrong guess can lock a device out): these probes only
look at what a device volunteers to anyone who connects.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import time


def tls_expired(ip: str, port: int = 443, timeout: float = 2.5) -> str | None:
    """Expiry date (YYYY-MM-DD) when the certificate is already expired, else None."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we only read the date, nothing is trusted or sent
    try:
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as tls:
                der = tls.getpeercert(binary_form=True)
        pem = ssl.DER_cert_to_PEM_cert(der)
        with tempfile.NamedTemporaryFile("w", suffix=".pem") as fh:
            fh.write(pem)
            fh.flush()
            info = ssl._ssl._test_decode_cert(fh.name)  # type: ignore[attr-defined]  # noqa: SLF001
        end = ssl.cert_time_to_seconds(info["notAfter"])
    except (OSError, ssl.SSLError, KeyError, ValueError, AttributeError, TypeError):
        return None
    return time.strftime("%Y-%m-%d", time.gmtime(end)) if end < time.time() else None


def ftp_anonymous(ip: str, port: int = 21, timeout: float = 3.0) -> bool:
    """True when the FTP server accepts the 'anonymous' user without a real password."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.recv(512)
            s.sendall(b"USER anonymous\r\n")
            s.recv(512)
            s.sendall(b"PASS kaa@local\r\n")
            ok = s.recv(512).startswith(b"230")
            s.sendall(b"QUIT\r\n")
            return ok
    except OSError:
        return False
