<p align="center"><img src="src/kaa/web/logo.svg" width="88" alt="Kaa"></p>

<h1 align="center">Kaa</h1>

<p align="center"><b>Your network. Your machine. Your data.</b></p>

Kaa watches your home network and tells you when something is wrong. It maps every device, recognises what each one is, and turns what it sees into a short list of things you can actually fix.

It is **sovereign**: everything runs on your computer, nothing is sent anywhere, and the AI that helps explain what it finds runs locally too.

## Install

```bash
pipx install git+https://github.com/yanickimhof/kaa
kaa update-data   # downloads the public vendor registry, once
kaa serve --open
```

Kaa needs Python 3.11 or later. On a Mac, add the menu bar item with `pipx install "kaa[menubar] @ git+https://github.com/yanickimhof/kaa"` and run `kaa menubar`.

## What you get

**A live map of every device** on your network, with its type, vendor and name, and what changed since yesterday.

**A health score you can act on.** Each issue comes with the evidence behind it and the exact step that fixes it.

**Alerts that matter.** A new device you did not approve. Your router's hardware address changing, the signature of a man-in-the-middle attack. UPnP quietly opening your router to the Internet. Telnet, FTP or Remote Desktop left on.

**AI that explains, never decides.** An optional local model can name devices that signatures cannot. It only proposes a type, its answers are limited to a fixed list, and it never sets how serious a problem is.

## Safe by design

- Listens on your computer only, and checks every request against a local token.
- Scans only private networks you own. Public addresses are refused before anything is sent.
- Passive and gentle by default. The port check is opt in (`Deep check`).
- No exploitation, no password guessing, no telemetry.

## Commands

| Command | Does |
|---|---|
| `kaa serve` | web app and background scanner |
| `kaa scan [--ports]` | one scan from the terminal |
| `kaa devices` | list what Kaa knows |
| `kaa doctor` | check setup and scope |
| `kaa menubar` | macOS menu bar item |

Configuration lives in `config.toml` inside Kaa's data folder (`kaa doctor` prints the path). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it works and [SECURITY.md](SECURITY.md) for the security model.

## License

MIT
