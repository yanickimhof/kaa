# Security model

Kaa is a security tool, so it holds itself to a strict standard.

## What Kaa will and will not do

| Will | Will not |
|---|---|
| Read the OS neighbour table, listen for mDNS and SSDP | Touch any address outside the private networks in scope |
| Open plain TCP connections to a short port list (opt in) | Send exploits, payloads or login attempts |
| Store everything in one local SQLite file | Send data off the machine without you enabling the feature, and never telemetry |
| Talk to a local AI endpoint you configure | Use a non loopback AI endpoint unless you set `ai.allow_remote` |

## Scope guard

Every active probe passes through `Scope.require`. Public, loopback and link-local
ranges are rejected when the scope is built. Scans larger than `max_hosts` are
refused. Per-device exclusions (`scan.exclude`) apply to every collector.

## Local web app

- Binds to loopback only; the config loader refuses any other host.
- Host header allow-list against DNS rebinding.
- State changing endpoints require a per-install token (`token` file, mode 0600)
  sent in a custom header, which cross-origin pages cannot send without a CORS
  preflight that Kaa never grants.
- Strict Content-Security-Policy; the UI builds DOM nodes and never uses `innerHTML`.

## AI layer

The model proposes a device class from a closed list, with confidence capped at
0.7, and only receives coarse metadata (vendor, hostname, services, ports), never
MAC or IP addresses. Findings and severities are produced by deterministic rules.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository.
