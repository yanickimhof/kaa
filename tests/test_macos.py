import subprocess

from kaa import macos


def _fake(ident, calls):
    def run(cmd, **kw):
        calls.append(cmd)
        if cmd[1] == "-dv":
            return subprocess.CompletedProcess(cmd, 0, "", f"Identifier={ident}\n")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return run


def test_unidentified_interpreter_is_signed_once(monkeypatch):
    calls = []
    monkeypatch.setattr(macos.sys, "platform", "darwin")
    monkeypatch.setattr(macos.subprocess, "run", _fake("-", calls))
    ok, msg = macos.ensure_identity("/py/python3.11")
    assert ok and macos.IDENTIFIER in msg
    assert any(c[:2] == ["codesign", "--force"] for c in calls)


def test_identified_interpreter_is_left_alone(monkeypatch):
    calls = []
    monkeypatch.setattr(macos.sys, "platform", "darwin")
    monkeypatch.setattr(macos.subprocess, "run", _fake("org.python.python", calls))
    ok, _ = macos.ensure_identity("/py/python3.11")
    assert ok and not any(c[1] == "--force" for c in calls)
