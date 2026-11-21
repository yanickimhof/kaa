# Contributing

Thanks for helping. Kaa stays small on purpose: local first, evidence first, no surprises.

## Set up

```bash
git clone https://github.com/yanickimhof/kaa && cd kaa
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest -q
python scripts/demo.py   # the interface with synthetic data, no scanning
# add ?still to the URL (and ?theme=light or dark) to freeze animations, for screenshots
```

## Easiest ways to help

- **Device signatures.** Add a rule to `src/kaa/data/signatures/*.yaml` and a test in `tests/test_identify.py`.
- **Translations.** Interface texts live in `src/kaa/web/i18n.js` (keep both languages in step) and alert texts in `src/kaa/texts.py`.
- **Bug reports.** Say your OS, Python version and what `kaa doctor` prints. Remove MAC and IP addresses first.

## Ground rules

- Findings and severities come from deterministic rules. A model may propose a device type, never a severity.
- No active probing beyond the private networks in scope, and nothing that exploits or guesses passwords.
- Anything that contacts the Internet must be opt in and listed in the README Privacy table.
- Keep tests free of real addresses and names. Use documentation ranges such as `192.168.50.x`.

Security issues: see [SECURITY.md](SECURITY.md).
