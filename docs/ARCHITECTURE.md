# Architecture

```
collectors ──► service cycle ──► SQLite ──► API ──► web app / menu bar
 arp, mdns,      discover          devices     FastAPI     map, devices,
 ssdp, tcp       identify          findings    loopback    actions
                 evaluate          events
                 score             scores
```

## Cycle

1. **Scope**: private networks from the active interfaces, or `scan.networks`.
2. **Discover**: gentle UDP sweep, then the OS ARP table. Local interfaces are added.
3. **Enrich**: vendor from the IEEE registry, reverse DNS, mDNS services, SSDP headers.
4. **Port check** (opt in): TCP connect on a short list.
5. **Identify**: signature rules (`src/kaa/data/signatures/*.yaml`) vote on a device
   class; agreeing rules reinforce each other. Only if nothing matches, and AI is
   enabled, a local model proposes a class.
6. **Evaluate**: deterministic rules in `findings.py` produce findings with evidence.
7. **Score**: 100 minus capped penalties per severity. Acknowledged findings keep their penalty and are reported as accepted risks.

Around the cycle, small optional workers run: Internet latency every 15 seconds,
Wi-Fi encryption (read only, macOS), the CISA catalogue, and the Internet exposure
check. Each is off or local unless you enable it; see the Privacy table in the README.

## Principles

- **Evidence first.** Every classification and finding stores what it was based on.
- **AI proposes, rules decide.** Severity never comes from a model.
- **Data, not code, for knowledge.** Signatures are YAML; add your own in the
  `signatures/` folder of Kaa's data directory, or contribute them upstream.
- **Layers.** Each later release adds engines behind the same evidence model.

## Roadmap

| Release | Adds |
|---|---|
| 0.1 | Inventory, identification, exposure checks, gateway watch, web app, menu bar |
| 0.2 | CVE correlation (NVD, CISA KEV, EPSS), vendor advisories |
| 0.3 | Traffic layer: Zeek and Suricata, DNS intelligence, behaviour baselines |
| 0.4 | Router adapters (UniFi, OpenWrt, Fritz!Box), router hardening audit |

## Data folder

`KAA_HOME`, or `~/Library/Application Support/Kaa` on macOS and
`~/.local/share/kaa` on Linux: `kaa.db`, `config.toml`, `token`, `data/oui.csv`,
`signatures/`.
