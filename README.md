# WarpShift-TUI

[![CI](https://img.shields.io/github/actions/workflow/status/RecursiveDev/WarpShift-TUI/ci.yml?label=CI)](https://github.com/RecursiveDev/WarpShift-TUI/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/RecursiveDev/WarpShift-TUI)](https://goreportcard.com/report/github.com/RecursiveDev/WarpShift-TUI)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.24-00ADD8?logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-blue)](#installation)

A minimalist Terminal User Interface for managing, rotating, and proxying [Cloudflare WARP](https://1.1.1.1/) connections. Built with [Bubble Tea](https://github.com/charmbracelet/bubbletea) and designed for local, privacy-conscious operation with explicit consent gates for advanced workflows.

## Features

- **Interactive TUI Dashboard** — Real-time WARP status, endpoint health, and connection management via a terminal UI.
- **CLI Command Surface** — Full subcommand interface for scripting and automation without the TUI.
- **Identity & Profile Management** — Import, inspect, and switch between multiple WARP identity profiles.
- **Endpoint Scanning & Pool** — Probe known Cloudflare WARP endpoints by latency and expand deterministic endpoint ranges.
- **Endpoint Rotation** — Automated rotation with latency, failure, and timed strategies; streaming/IP rotation with consent gates.
- **SOCKS5 & HTTP Proxy** — Dual-protocol proxy with WARP tunnel backend, client allowlists, authentication, and rate limiting.
- **WireGuard Profile Export** — Generate `.wg.conf` profiles from stored identities with configurable MTU and auto-detection.
- **Account & License Management** — Register devices, check status, bind WARP+ licenses — all consent-gated.
- **Safety-First Design** — Paired consent gates for account automation, streaming unlock, and WARP+ workflows.
- **Docker & Compose Support** — Multi-stage Dockerfile with non-root user, healthcheck, and compose configuration for interactive TUI usage.

## Requirements

- **Go 1.24+** (for building from source)
- **Docker** (optional, for container-based usage)
- A valid **Cloudflare WARP identity** (JSON format, manually imported)

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/RecursiveDev/WarpShift-TUI.git
cd WarpShift-TUI

# Build for current platform
make build

# The binary is at build/warpshift (or build/warpshift.exe on Windows)
```

### Cross-Compile

```bash
# Build for linux, darwin, and windows (amd64 + arm64)
make build-all

# Artifacts are placed in dist/
```

### Docker

```bash
# Build the image
make docker

# Or use compose for interactive TUI usage
docker compose build
docker compose up
```

## Usage

### Interactive TUI

```bash
# Launch the TUI dashboard
./build/warpshift tui
```

### CLI Subcommands

```bash
# Show version
warpshift version

# Validate configuration
warpshift config validate --config configs/warpshift.example.toml

# Import a WARP identity
warpshift identity import --input configs/warpshift.identity.json

# Manage profiles
warpshift profile import --name home --input configs/warpshift.identity.json
warpshift profile list
warpshift profile show --name home
warpshift profile switch --name home
warpshift profile delete --name home

# Scan endpoints by latency
warpshift endpoint scan --static "162.159.192.10:2408,162.159.193.20:2408"

# Expand deterministic endpoint pool
warpshift endpoint pool --port 2408,2408 --ipv6

# Export a WireGuard profile
warpshift wireguard export --identity configs/warpshift.identity.json

# MTU auto-detection helper
warpshift wireguard mtu

# Rotation planning and reporting (local data)
warpshift rotation inspect
warpshift rotation plan
warpshift rotation report

# Rotation run (requires streaming_unlock consent in config)
warpshift rotation run --config configs/warpshift.local.toml

# Proxy operations
warpshift proxy validate --identity configs/warpshift.identity.json
warpshift proxy start --identity configs/warpshift.identity.json --endpoint "162.159.192.10:2408"

# Account & license management (requires consent flags in config)
warpshift account register --config configs/warpshift.local.toml
warpshift account status
warpshift license bind --license-key YOUR-KEY
warpshift license status

# Parse Cloudflare trace output
warpshift trace parse --file trace.txt
```

### Docker Compose One-Off Commands

```bash
# Validate config inside the container
docker compose run --rm warpshift config validate

# Import identity
docker compose run --rm warpshift identity import --input /home/warpshift/configs/warpshift.identity.json

# Export WireGuard profile
docker compose run --rm warpshift wireguard export
```

## Configuration

WarpShift-TUI uses TOML configuration. Copy the example and customize:

```bash
cp configs/warpshift.example.toml configs/warpshift.local.toml
```

| Section    | Key Settings                                          | Description                                           |
| ---------- | ----------------------------------------------------- | ----------------------------------------------------- |
| `[app]`    | `startup_mode`                                        | Application startup mode (`tui`, `cli`)               |
| `[warp]`   | `status_source`                                       | WARP status source (`local`)                          |
| `[endpoint]`| `static`                                              | Static WARP endpoint list for scanning                |
| `[rotation]`| `strategies`, `max_attempts`, `cooldown_seconds`      | Rotation policy and timing                            |
| `[identity]`| `store_path`                                          | Path to local identity JSON store                     |
| `[wireguard]`| `endpoint`, `mtu`, `auto_mtu`                       | WireGuard profile generation settings                 |
| `[proxy]`  | `listen_address`, `allowed_client_cidrs`, `tls_mode`  | Proxy listener and security settings                  |
| `[safety]` | `account_automation`, `streaming_unlock`, etc.         | Paired consent flags for advanced workflows           |

See [`configs/warpshift.example.toml`](configs/warpshift.example.toml) for the full annotated reference.

## Makefile Targets

| Target              | Description                                  |
| ------------------- | -------------------------------------------- |
| `make build`        | Build binary for current OS/arch             |
| `make build-all`    | Cross-compile for linux, darwin, windows     |
| `make test`         | Run Go tests with race detection             |
| `make vet`          | Run `go vet`                                 |
| `make lint`         | Run `golangci-lint` (requires local install) |
| `make cover`        | Run tests and open HTML coverage report      |
| `make release`      | Clean and build all release binaries         |
| `make docker`       | Build Docker image                           |
| `make docker-compose-up` | Start with docker compose               |
| `make clean`        | Remove build artifacts                       |
| `make help`         | Show all available targets                   |

## Project Structure

```
WarpShift-TUI/
├── cmd/warpshift/          # Application entrypoint
│   ├── main.go             # Signal handling, CLI dispatch
│   └── main_test.go
├── internal/
│   ├── app/                # Application metadata and capabilities
│   ├── cli/                # CLI command surface (all subcommands)
│   ├── config/             # TOML configuration loading
│   ├── proxy/              # SOCKS5 and HTTP proxy server
│   ├── tui/                # Bubble Tea terminal dashboard
│   ├── tunnel/             # Userspace WireGuard tunnel + MTU detection
│   └── warp/               # WARP identity, endpoints, rotation, health, API
├── configs/
│   └── warpshift.example.toml  # Annotated example configuration
├── build/                  # Build output (git-ignored)
├── .github/workflows/
│   └── ci.yml              # CI: test matrix, binary build, Docker verification
├── Dockerfile              # Multi-stage build, non-root user, healthcheck
├── docker-compose.yml      # Interactive TUI with config mounts
├── Makefile                # Build, test, lint, release, Docker targets
└── LICENSE                 # MIT License
```

## Safety & Security

WarpShift-TUI is designed for **local, private-use operation**. Key safety features:

- **Paired Consent Gates** — Advanced workflows (account registration, streaming rotation, WARP+ license binding) require both a feature flag and a matching consent flag in the `[safety]` configuration section. Both must be `true` for the workflow to activate. See [`docs/architecture/ADR-001-safety-consent-architecture.md`](docs/architecture/ADR-001-safety-consent-architecture.md) for details.
- **Local-First** — No telemetry, no remote analytics. All state is stored locally.
- **Secret-Safe Defaults** — Identity files, WireGuard configs, and local config overrides are git-ignored by default.
- **Rate Limiting & Allowlists** — Proxy listeners default to localhost-only with per-client connection budgets.
- **Non-Root Docker** — Container runs as a dedicated `warpshift` user with resource limits.
- **DPI Evasion (Not Implemented)** — The `dpi_evasion` config flags exist but no runtime DPI evasion logic is active. See [`docs/architecture/ADR-002-dpi-evasion-deferred.md`](docs/architecture/ADR-002-dpi-evasion-deferred.md).
- **TLS Proxy Mode (Not Implemented)** — The `tls_mode` config field exists but only `"disabled"` has an effect. See [`docs/architecture/ADR-003-tls-proxy-mode-deferred.md`](docs/architecture/ADR-003-tls-proxy-mode-deferred.md).

> **Important:** This tool is intended for managing WARP connections on accounts and networks you own or are authorized to use. Users are responsible for compliance with Cloudflare's terms of service.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on reporting issues, submitting pull requests, and development setup.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Support

See [SUPPORT.md](SUPPORT.md) for getting help and filing bug reports.

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy.

## Architecture Decisions

Architecture decision records are located in [`docs/architecture/`](docs/architecture/):

- [ADR-001: Safety and Consent Gate Architecture](docs/architecture/ADR-001-safety-consent-architecture.md) — How paired consent flags protect sensitive workflows.
- [ADR-002: DPI Evasion — Deferred Scope](docs/architecture/ADR-002-dpi-evasion-deferred.md) — Why DPI evasion config exists but runtime is not implemented.
- [ADR-003: TLS Proxy Mode — Deferred Scope](docs/architecture/ADR-003-tls-proxy-mode-deferred.md) — Why `tls_mode` is parsed but only `"disabled"` has effect.
- [ADR-004: Bubble Tea v2 Migration — Deferred](docs/architecture/ADR-004-bubbletea-v2-migration-deferred.md) — Why the TUI remains on Bubble Tea v1.

## Disclaimer

WarpShift-TUI is an **independent, open-source project** and is **not affiliated with, endorsed by, or sponsored by Cloudflare, Inc.**

- "Cloudflare WARP", "1.1.1.1", "WARP+", and the Cloudflare logo are trademarks of Cloudflare, Inc.
- This project interacts with Cloudflare's public WARP client API using user-provided credentials. It does not modify, redistribute, or wrap any Cloudflare software.
- "Cloudflare" is used in this documentation solely to identify the service that this tool is designed to manage.
- No Cloudflare intellectual property is included in this repository. All code is original and licensed under the [MIT License](LICENSE).
- Users are solely responsible for compliance with [Cloudflare's Terms of Service](https://www.cloudflare.com/terms/) and applicable laws when using this tool.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 RecursiveDev
