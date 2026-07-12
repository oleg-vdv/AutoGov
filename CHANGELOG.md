# Changelog

All notable changes to this project are documented here. Format loosely follows 
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.1.0] — 2026-07-12

First MVP release — Stage E1 (M1 Discovery for n8n), pilot-ready.

### Added
- **Platform core (E0):** universal data model (privacy by design), in-process
  event bus, embedded asset/findings store (JSON snapshot + JSONL audit,
  idempotent ingest), plugin-based Module Runtime.
- **M1 Discovery:** multi-signal n8n detection (Docker, processes, network
  fingerprint, filesystem, cron/systemd), asset inventory, “instance →
  credentials → target systems” reachability map, configurable risk scoring
  with local RU/EN explanations, whitelisting.
- **Agent:** outbound-only sensor with graceful degradation, secret sanitizer
  (values never leave the host — SHA-256 fingerprints only), disk spool, mTLS
  client.
- **Control plane:** ingest API with dedup, public REST API, RBAC
  (viewer/analyst/admin), audit log, embedded web dashboard.
- **Notifications:** syslog/CEF (Wazuh/Splunk), webhook, email, Telegram — with
  an on-prem egress guard (blocks external destinations by default).
- **Reports:** JSON / CSV / PDF (dependency-free PDF generator).
- **Signed artifacts (`autogov-sign`):** ed25519-signed release manifest; the
  agent verifies its own binary hash at startup and refuses to run if tampered
  (fail-closed).
- **M2–M4 plugin stubs** proving the platform contract with zero core changes.
- Deploy: Docker Compose demo stack with a shadow n8n; CI (fmt/vet/build/test).

### Fixed
- Docker-derived reachability (postgres backend, secret-env targets) is now
  scored on the first observation instead of only after a later rescan.
- Process detection no longer false-positives on shells that merely mention an
  `N8N_*` env var (requires an actual n8n binary token).
