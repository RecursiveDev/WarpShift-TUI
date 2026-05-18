# Contributing to WarpShift-TUI

Thank you for your interest in contributing to WarpShift-TUI. This document covers how to report issues, submit changes, and set up your development environment.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Reporting Issues](#reporting-issues)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Commit Messages](#commit-messages)

## Code of Conduct

Be respectful and constructive in all interactions. Assume good intent and focus on technical merit.

## Getting Started

### Prerequisites

- **Go 1.24+** — [Download Go](https://go.dev/dl/)
- **golangci-lint** (optional) — for local linting
- **Docker** (optional) — for container-based development

### Setup

```bash
# Clone and enter the repository
git clone https://github.com/RecursiveDev/WarpShift-TUI.git
cd WarpShift-TUI

# Download dependencies
go mod download

# Run the test suite
make test

# Run static analysis
make vet

# Run linter (requires golangci-lint)
make lint

# Build and verify
make build
./build/warpshift version
```

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/my-change
   ```
3. **Make your changes** with tests.
4. **Verify locally:**
   ```bash
   make test
   make vet
   make build
   ```
5. **Commit** using the conventions below.
6. **Push** and open a pull request.

### Test Requirements

- All new functionality must include tests.
- Run the full test suite with race detection before submitting:
  ```bash
  make test
  ```
- Aim for meaningful coverage, not arbitrary percentages.

## Reporting Issues

Open a [GitHub issue](https://github.com/RecursiveDev/WarpShift-TUI/issues) with:

- A clear title describing the problem.
- Steps to reproduce (commands, config, expected vs actual behavior).
- Environment details: OS, Go version, WarpShift-TUI version.
- Relevant config excerpts (redact secrets and identity material).

## Submitting Changes

### Pull Request Guidelines

- Keep PRs focused on a single change.
- Include a clear description of **what** changed and **why**.
- Reference related issues (e.g., `Fixes #42`).
- Ensure CI passes (tests, vet, build on all platforms).

### What Makes a Good PR

- Small, reviewable diff.
- Tests covering new behavior and edge cases.
- Documentation updates if the public interface or config changes.
- No unrelated formatting or refactoring changes.

## Code Style

This project follows standard Go conventions:

- Run `go vet ./...` — no warnings.
- Run `golangci-lint run ././...` — clean report.
- Use `gofmt` / `goimports` for formatting.
- Prefer clarity over cleverness.
- Keep packages focused with clear boundaries (`internal/cli`, `internal/warp`, etc.).
- Use dependency injection (functional options) for testability — see `internal/cli/cli.go` for the pattern.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>(<scope>): <description>

[optional body]
```

### Types

| Type       | Description                               |
| ---------- | ----------------------------------------- |
| `feat`     | New feature                               |
| `fix`      | Bug fix                                   |
| `docs`     | Documentation only                        |
| `style`    | Formatting, no code change                |
| `refactor` | Code restructuring, no behavior change    |
| `test`     | Adding or updating tests                  |
| `chore`    | Build, CI, tooling changes                |
| `perf`     | Performance improvement                   |

### Scopes

Common scopes: `tui`, `cli`, `config`, `proxy`, `tunnel`, `warp`, `build`, `ci`, `docs`.

### Examples

```
feat(tui): add endpoint health panel to dashboard
fix(proxy): close listener on context cancellation
docs(readme): add Docker compose usage section
test(warp): add rotation policy edge case coverage
chore(build): update Makefile with cover target
```

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
