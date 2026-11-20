from __future__ import annotations

import argparse
import sys
import threading
import webbrowser

from . import __version__
from . import config as config_mod
from .db import Database
from .scope import ScopeError, build_scope, local_interfaces
from .service import Service


def _boot() -> tuple[config_mod.Config, Database, Service]:
    cfg = config_mod.load()
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(cfg.db_path)
    return cfg, db, Service(cfg, db)


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from .api import create_app

    cfg, db, service = _boot()
    token = config_mod.load_token(cfg)
    stop = threading.Event()
    if not service.oui.loaded:
        print("Vendor names need the IEEE registry: run `kaa update-data` once.")
    threading.Thread(target=service.loop, args=(stop,), daemon=True).start()
    url = f"http://{cfg.host}:{cfg.port}"
    print(f"Kaa {__version__} on {url}  (data: {cfg.home})")
    if args.open:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        uvicorn.run(create_app(service, token), host=cfg.host, port=cfg.port,
                    log_level="warning")
    finally:
        stop.set()
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    _cfg, db, service = _boot()
    service.run_cycle(ports=args.ports)
    if service.state["last_error"]:
        print("error:", service.state["last_error"], file=sys.stderr)
        return 1
    s = service.summary()
    print(f"Score {s['score']['value']} ({s['score']['grade']}), "
          f"{s['devices']} devices, {s['open_findings']} open findings")
    return 0


def cmd_devices(_args: argparse.Namespace) -> int:
    _cfg, db, _service = _boot()
    for d in db.list_devices():
        name = d["label"] or d["hostname"] or d["vendor"] or "?"
        print(f"{'●' if d['online'] else '○'} {d['ip'] or '-':15} {d['mac']}  "
              f"{d['class']:12} {d['class_conf']:.2f}  {name}")
    return 0


def cmd_update_data(_args: argparse.Namespace) -> int:
    from . import oui

    cfg = config_mod.load()
    size = oui.download(cfg.data_dir / "oui.csv")
    print(f"IEEE registry updated ({size // 1024} KiB).")
    return 0


def cmd_doctor(_args: argparse.Namespace) -> int:
    cfg = config_mod.load()
    print(f"Kaa {__version__}")
    print(f"Data folder : {cfg.home}")
    print(f"Vendor table: {'ok' if (cfg.data_dir / 'oui.csv').exists() else 'missing, run `kaa update-data`'}")
    for i in local_interfaces():
        print(f"Interface   : {i.name} {i.ip} in {i.network}")
    try:
        scope = build_scope(cfg.networks, cfg.max_hosts, cfg.exclude)
        print(f"Scope       : {', '.join(scope.describe())}")
    except ScopeError as exc:
        print(f"Scope       : PROBLEM, {exc}")
        return 1
    print(f"Port scan   : {'on' if cfg.portscan else 'off (opt in with `kaa scan --ports`)'}")
    print(f"AI resolver : {'on, ' + cfg.ai_endpoint if cfg.ai_enabled else 'off'}")
    return 0


def cmd_menubar(_args: argparse.Namespace) -> int:
    from .menubar import run

    cfg = config_mod.load()
    run(f"http://{cfg.host}:{cfg.port}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="kaa", description="Sovereign home network analyzer")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", help="run the web app and the background scanner")
    s.add_argument("--open", action="store_true", help="open the browser")
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("scan", help="run one scan now")
    s.add_argument("--ports", action="store_true", help="include the TCP port check")
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("devices", help="list known devices").set_defaults(fn=cmd_devices)
    sub.add_parser("update-data", help="download the IEEE vendor registry").set_defaults(fn=cmd_update_data)
    sub.add_parser("doctor", help="check setup and scope").set_defaults(fn=cmd_doctor)
    sub.add_parser("menubar", help="macOS menu bar item").set_defaults(fn=cmd_menubar)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
