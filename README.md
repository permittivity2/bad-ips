# 🛡️ Bad IPs - Distributed IP Blocking System

[![Version](https://img.shields.io/badge/version-3.5.0-blue.svg)](https://github.com/permittivity2/bad-ips/releases)
[![Status](https://img.shields.io/badge/status-ALPHA-red.svg)](https://github.com/permittivity2/bad-ips)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu-orange.svg)](https://projects.thedude.vip/bad-ips/)

# BadIPs

BadIPs is a distributed, log-driven IP blocking daemon for Linux systems built around nftables, Perl, and an optional central PostgreSQL database.

It monitors logs from systemd journald units and/or plain log files, detects suspicious activity using configurable patterns, blocks offending IPs locally using nftables sets with timeouts, and can optionally share those blocks across an entire server fleet.

This is **not Fail2ban**.  
BadIPs is a coordinated, deterministic, network-wide ban system intended for environments with multiple servers and a desire for shared intelligence and predictable behavior.

---

## Why BadIPs Exists

Fail2ban works well on a single host, but it becomes harder to reason about at scale. It does not natively share bans across machines, provides limited long-term visibility into why an IP was banned, and can be awkward to reload or extend cleanly in more complex environments.

BadIPs was designed to address these issues by clearly separating detection, blocking, and synchronization. It allows bans to be shared across hosts when desired, uses nftables sets with timeouts for efficient blocking, and emphasizes explicit control, clarity, and debuggability.

---

## High-Level Architecture

BadIPs runs as a single supervisor process that manages multiple worker threads. All communication happens via thread-safe queues.

Logs (journald units and files)  
→ Pattern matching and detection  
→ IP extraction  
→ ips_to_block_queue  
→ nft_blocker thread → nftables sets (with TTL)  
→ sync_to_central_db_queue  
→ central_db_sync thread → PostgreSQL  
← pull_global_blocks thread ← PostgreSQL  

No worker directly calls another worker. Shutdowns and reloads are coordinated via shared flags.

---

## Core Features

### Log-Driven Blocking

- Reads from systemd journald units and plain log files
- Supports IPv4 and IPv6
- Uses configurable regular expression patterns
- Extracts all IPs from matching log lines

### nftables-Native

- Uses nftables sets with timeouts
- No rule churn
- Fast lookups
- Clean expiration handling

### Distributed Intelligence (Optional)

- Blocks detected on one host can be shared with all hosts
- Uses PostgreSQL as a coordination backend
- Prevents re-learning the same attackers everywhere

### Public Blocklist Plugins

- Plugin framework for external blocklists
- Each plugin runs in its own thread
- Plugins enqueue IPs using the same mechanism as detectors
- External data ingestion is isolated from core logic

### Safe Reloads

- SIGHUP triggers:
  - worker shutdown
  - configuration reload
  - nftables static set refresh
  - worker restart
- No process restart required
- Designed to avoid partial or inconsistent state

### Graceful Shutdown

- Queues are drained
- Workers are joined cleanly
- Timeouts are enforced
- Remaining work is logged explicitly

---

## What This Is Not

- Not a GUI tool
- Not a firewall frontend
- Not an IDS or IPS replacement
- Not heuristic or machine-learning based
- Not “magic”

BadIPs is intentionally deterministic.

---

## Installation Overview

BadIPs is currently alpha software and intended for controlled environments.

A typical installation involves installing Perl dependencies, creating the required nftables sets, optionally provisioning a PostgreSQL database, configuring `badips.conf` and detector configuration files, and starting the daemon. Packaging as a `.deb` is recommended for real deployments.

---

## Configuration Overview

The main configuration file defines nftables details, database connectivity, timing parameters, and global defaults.

Detector configuration files define log sources and matching patterns. Detectors may contribute journald units, file sources, and regular expression patterns. All detector inputs are merged at runtime.

---

## Public Blocklist Plugins

BadIPs supports public blocklist plugins. Each plugin runs in its own thread, fetches and processes its own data, and enqueues IPs for blocking using the same mechanism as log-based detectors. Plugins respect reload and shutdown signals.

---

## Signals

| Signal   | Behavior |
|----------|----------|
| SIGTERM  | Graceful shutdown |
| SIGINT   | Graceful shutdown |
| SIGQUIT  | Graceful shutdown |
| SIGHUP   | Reload configuration and restart workers |

---

## Logging

BadIPs uses Log::Log4perl for logging. Thread names are injected into the logging context. Log configuration changes can be detected and trigger worker reloads.

---

## Status

BadIPs is alpha software. It is used in real environments by the author but is still evolving. Expect configuration changes, additional documentation, and new plugins over time.

---

## Philosophy

Make it obvious.  
Make it boring.  
Make it correct.

BadIPs favors clarity over cleverness, explicit control over heuristics, and debuggability over magic.

