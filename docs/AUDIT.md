# Review notes (0.1.0)

A self review of code, security, performance and usability, done by the maintainers with static analysis
(ruff with the security rules, pip-audit) and manual reading. It is **not an independent audit**. Findings
are listed with what was done, so you can judge for yourself.

## Summary

| Area | Result |
|---|---|
| Dependencies | pip-audit: no known vulnerabilities in the installed dependencies at review time (versions are not pinned) |
| Static analysis | no injection, unsafe deserialisation or shell use found; remaining notes below |
| Local API | loopback only, host allow list, per-install token on every state changing route (tested) |
| Performance | every API call answers in under 40 ms with 43 devices; the UI pauses polling when hidden |
| Usability | contrast, keyboard focus, reduced motion and dialog semantics reviewed and fixed |
| Tests | 97 tests, run on Linux and macOS in CI |

## Fixed during the review

| Finding | Severity | Fix |
|---|---|---|
| Data folder readable by other local users (inventory of your network) | Medium | folder set to mode 0700 |
| Event, score and speed test tables grew without limit | Medium | daily pruning: 90 days of events and scores, one year of speed tests; the inventory is kept |
| AI endpoint accepted any URL scheme (for example `file:`) | Low | only `http` and `https` accepted |
| Settings with control characters could corrupt `config.toml` | Low | control characters are escaped; round trip tested |
| Strict Content Security Policy lacked `base-uri`, `form-action`, `object-src` | Low | added; `Cache-Control: no-store` on API answers |
| Health score hid accepted risks (acknowledging made the score rise) | Product | accepted risks keep their penalty and are shown next to the score |
| Light theme status colours below 4.5:1 contrast | Usability | darker values |
| No visible keyboard focus, no reduced motion support, drawer without dialog semantics | Usability | focus ring, `prefers-reduced-motion`, `role="dialog"`, focus moves in and back |
| Page kept refreshing in a background tab | Performance | polling pauses while hidden |
| Retired weekly report endpoint still served | Hygiene | removed |

## Accepted limitations

- **Anything running as your user can read the local token and call the API.** The token protects against web pages and other users, not against local malware.
- **The expired certificate probe does not verify certificates.** It only reads the expiry date and sends nothing.
- **`'unsafe-inline'` styles are allowed** because the interface sets style attributes. Scripts are strictly `self`.
- **Firmware versions cannot be read.** Kaa matches known exploited flaws by vendor and model, and reminds you to check firmware by hand.
- **The scan sees what the network shows.** A device that stays silent, uses a different VLAN or blocks probes is invisible.
- **No signed releases or SBOM yet.** Install from the repository and review the code.

## Maintainability notes

- `service.py` is the largest module (about 800 lines) and mixes scanning, evaluation and presentation helpers. Splitting it is the next refactor.
- The front end is a single vanilla module with no build step on purpose.

Report issues privately as described in [SECURITY.md](../SECURITY.md).
