# Changelog

All notable changes to WarpShift-TUI are documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- CI: GitHub Actions workflow for test, build, and Docker verification (`ci.yml`).
  - Go test matrix with race detection on Go 1.24 and 1.25.
  - Binary build verification on Linux, macOS, and Windows.
  - Docker image build verification with Buildx and GHA cache.
- Multi-stage Dockerfile with non-root user and healthcheck.
- Docker Compose configuration for interactive TUI usage with config mounts.
- Makefile with build, test, vet, lint, cover, release, docker, and clean targets.
- Comprehensive README with shields, usage guide, and project structure.
- Community documentation: CONTRIBUTING.md, SECURITY.md, SUPPORT.md, CHANGELOG.md.

### Changed

- Dashboard, identity, and help copy updated to reflect explicit consent requirements for API and streaming workflows.

### Fixed

- Consent-gated workflows now use paired flags (feature flag + consent flag) instead of hard safety denials.

## [Initial Development]

### Added

- **CLI Command Surface** — Full subcommand interface: `tui`, `config`, `identity`, `profile`, `wireguard`, `trace`, `endpoint`, `rotation`, `proxy`, `account`, `license`.
- **Interactive TUI** — Bubble Tea terminal dashboard with real-time WARP status.
- **Profile Management** — `profile import`, `list`, `show`, `switch`, `delete` for named WARP identity profiles.
- **Endpoint Scanning** — `endpoint scan` with configurable static sources and RTT ranking.
- **Endpoint Pool** — `endpoint pool` for deterministic WARP endpoint range expansion with IPv4/IPv6 support.
- **Rotation Engine** — `rotation inspect`, `plan`, `run`, `report` with latency, failure, and timed strategies.
- **Streaming/IP Rotation** — Consent-gated streaming rotation executor with target probing and history persistence.
- **Proxy Server** — SOCKS5 and HTTP proxy with WARP tunnel backend, client CIDR allowlists, per-client rate limiting, and authentication.
- **WireGuard Export** — `wireguard export` to generate `.wg.conf` profiles from stored identities.
- **MTU Detection** — `wireguard mtu` helper with configurable bounds and fallback.
- **Identity Management** — `identity import` and `inspect` for local WARP identity JSON files.
- **Account Automation** — `account register`, `status`, `delete` with consent gates for Cloudflare WARP API.
- **License Management** — `license bind`, `status` for user-owned WARP+ license keys.
- **Trace Parsing** — `trace parse` and `trace status` for Cloudflare trace output.
- **Configuration System** — TOML-based configuration with validation, defaults, and safety consent flags.
- **Safety Framework** — Paired consent gates (`account_automation`/`account_automation_consent`, `streaming_unlock`/`streaming_unlock_consent`, `warp_plus_generation`/`warp_plus_generation_consent`, `dpi_evasion`/`dpi_evasion_consent`).
- **Tunnel Backend** — Userspace WireGuard via `golang.zx2c4.com/wireguard` with `gvisor` netstack.
- **Test Suite** — Unit tests, benchmarks, and race-safe test patterns with dependency injection throughout.
