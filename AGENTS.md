# Repository Guidelines

## Project Structure
- `cmd/warpshift/` contains the application entrypoint, signal handling, version injection, and CLI dispatch.
- `internal/cli/` implements the command surface; keep command dependencies injectable through options so tests avoid live network behavior.
- `internal/config/` loads and validates TOML settings from `configs/warpshift.example.toml` and local overrides.
- `internal/tui/`, `internal/proxy/`, `internal/tunnel/`, and `internal/warp/` hold the Bubble Tea UI, SOCKS5/HTTP proxy, userspace WireGuard helpers, and WARP domain logic.
- `configs/` contains the annotated example config only; local configs, identity JSON, and generated WireGuard profiles are git-ignored secrets.
- `build/`, `dist/`, and `coverage.out` are generated outputs and should not be committed.

## Development Commands
- `go mod download`: Download Go module dependencies after clone.
- `cp configs/warpshift.example.toml configs/warpshift.local.toml`: Create a local config; customize it without committing it.
- `make build`: Build `./cmd/warpshift` into `build/warpshift` or `build/warpshift.exe`.
- `./build/warpshift tui`: Run the interactive TUI after building.
- `./build/warpshift config validate --config configs/warpshift.example.toml`: Validate the checked-in example config.
- `make test`: Run all Go tests with race detection via `go test -race -count=1 ./...`.
- `go test -race -count=1 ./internal/warp -run TestName`: Run one package/test; replace package path and test name as needed.
- `make vet`: Run `go vet ./...`.
- `make lint`: Run `golangci-lint run ./...`; requires a local `golangci-lint` install.
- `make cover`: Generate `coverage.out` and open an HTML coverage report.
- `make build-all`: Cross-compile release binaries into `dist/` for Linux, macOS, and Windows.
- `make docker`: Build the local Docker image; use `docker compose build` and `docker compose up` for interactive Compose usage.
- No separate typecheck or dev-server target is defined; `make build` and `make test` provide compile/type verification.

## Coding Conventions
- Use Go 1.24+ and the module path `github.com/RecursiveDev/WarpShift-TUI`.
- Format Go code with `gofmt`/`goimports`; keep `go vet ./...` and `golangci-lint run ./...` clean.
- Keep packages focused on the existing `internal/*` boundaries; do not bypass `internal/cli` for user-facing command behavior.
- Prefer dependency injection and functional options for network probes, TUI launchers, dialers, and tick sources, following `internal/cli/cli.go` and `internal/warp/rotator.go`.
- Return errors instead of exiting in library/internal packages; only `cmd/warpshift/main.go` should call `os.Exit`.
- Preserve local-first, secret-safe behavior: do not add telemetry or live account/network operations without the existing explicit safety consent gates.

## Testing & Verification
- Tests live beside code as `*_test.go` under `cmd/` and `internal/`; benchmarks use `*_benchmark_test.go` names in the same packages.
- Use injected fakes for network, tunnel, timing, and TUI dependencies; existing tests avoid live probes by default.
- Before submitting code changes, run at least the focused `go test -race -count=1 <package> -run <TestName>` that covers the edit, then the broader relevant check (`make test`, `make vet`, `make build`, or `make lint`).
- CI runs `go vet ./...`, `go test -race -coverprofile=coverage.out -covermode=atomic ./...`, golangci-lint, cross-platform builds, Docker build verification, and CodeQL.
- For config changes, include `./build/warpshift config validate --config configs/warpshift.example.toml` after rebuilding.

## Safety & Change Management
- Preserve unrelated user changes; inspect `git status --short` before editing and avoid files outside the requested scope.
- Keep this `AGENTS.md` dynamic and minimal; update it with concise, evidence-based guidance when major repository changes make existing instructions obsolete.
- Use strict Conventional Commits 1.0.0 with no emojis, matching scopes such as `tui`, `cli`, `config`, `proxy`, `tunnel`, `warp`, `build`, `ci`, and `docs`.
- Split unrelated logical concerns into multiple atomic commits by default; use one commit only when the full diff is one logical unit or the user explicitly approves a mixed-concern commit.
- Do not edit generated outputs, vendored code, lock files such as `go.sum`, migrations, or environment/local-secret files unless the task explicitly requires it.
- Never commit `configs/warpshift.local.toml`, WARP identity JSON, WireGuard profiles, `.env*`, logs, or coverage/build artifacts.
- Keep advanced workflows consent-gated: account automation, WARP+ license actions, DPI evasion, and streaming rotation require paired feature and consent flags in config.

## Agent Notes
- Start with `README.md`, `CONTRIBUTING.md`, `Makefile`, `.github/workflows/ci.yml`, and `configs/warpshift.example.toml` for repository-specific behavior.
- The binary name is `warpshift`; version strings are injected through the Makefile linker flag into `main.version`.
- Docker and Compose are intended for local interactive use, not production server deployment.
- Public-facing config and CLI behavior should stay documented in `README.md` and reflected in `configs/warpshift.example.toml`.
