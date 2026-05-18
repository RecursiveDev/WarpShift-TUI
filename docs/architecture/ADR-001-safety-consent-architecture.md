# ADR-001: Safety and Consent Gate Architecture

## Status

Accepted

## Context

WarpShift-TUI operates against a third-party service (Cloudflare WARP) using user-provided credentials. Several workflows — account registration, license binding, streaming rotation, and DPI evasion — interact with live APIs or manipulate network traffic in ways that carry risk if activated accidentally or without the user's understanding.

The project needs a uniform mechanism that prevents accidental activation of sensitive workflows while keeping the configuration surface stable and self-documenting.

## Decision

Every sensitive workflow requires **two paired boolean flags** in the `[safety]` configuration section:

| Feature Flag                   | Consent Flag                            | Protected Workflow                      |
| ------------------------------ | --------------------------------------- | --------------------------------------- |
| `account_automation`           | `account_automation_consent`            | `account register`, `account status`, `account delete` |
| `warp_plus_generation`         | `warp_plus_generation_consent`          | `license bind`, `license status`        |
| `streaming_unlock`             | `streaming_unlock_consent`              | `rotation run`                          |
| `dpi_evasion`                  | `dpi_evasion_consent`                   | DPI evasion (not yet implemented)       |

### How it works

1. **Config validation** (`internal/config/config.go`, `ValidateIssues`) checks that if a feature flag is `true`, its matching consent flag must also be `true`. If the feature flag is enabled without the consent flag, a `ValidationIssue` is returned with a descriptive message and fix hint.

2. **Command-level gating** (`internal/cli/cli.go`) checks both flags at the start of each protected subcommand (e.g., `loadAccountConsent`, `loadWARPPlusConsent`, `loadStreamingConsent`). If either flag is missing, the command prints a descriptive error and exits with code 2.

3. **API-level gating** (`internal/warp/api.go`) functions like `RegisterAccount` accept `ExplicitConsent` and `AcknowledgedGate` booleans. If either is `false`, the function returns `ErrAccountAutomationConsentRequired` without making any network call.

### Design principles

- **Both flags must be `true`**: Setting a feature flag without its consent flag is a configuration error. Setting a consent flag without the feature flag has no effect.
- **Conservative defaults**: All flags default to `false`. No workflow runs without explicit opt-in.
- **No silent bypasses**: Every code path that touches a gated workflow checks consent before doing anything irreversible.
- **Self-documenting**: The example TOML (`configs/warpshift.example.toml`) includes inline comments explaining each pair.

## Consequences

- Users who enable advanced workflows must deliberately set two flags, reducing accidental activation.
- The configuration surface is stable: flags can be added without removing existing ones.
- Features that are not yet implemented (e.g., DPI evasion) still have their flags defined and validated; they reject activation gracefully rather than silently doing nothing.
