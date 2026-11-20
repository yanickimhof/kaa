import plistlib

from kaa import launchd
from kaa.cli import main


def test_plist_runs_serve_in_background_without_restart_loops(env):
    cfg, _db, _s = env
    data = plistlib.loads(plistlib.dumps(launchd.build_plist(cfg, python="/venv/bin/python")))
    assert data["ProgramArguments"] == ["/venv/bin/python", "-m", "kaa.cli", "serve"]
    assert "--open" not in data["ProgramArguments"]  # a background service must not pop a browser
    assert data["RunAtLoad"] is True
    assert data["KeepAlive"] == {"SuccessfulExit": False}
    assert data["ThrottleInterval"] >= 30
    assert data["StandardOutPath"].endswith("kaa.log")
    assert data["EnvironmentVariables"]["KAA_HOME"] == str(cfg.home)


def test_service_refuses_off_macos(env, monkeypatch, capsys):
    monkeypatch.setattr(launchd.sys, "platform", "linux")
    assert main(["service", "install"]) == 1
    assert "macOS only" in capsys.readouterr().err
