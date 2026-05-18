# ADR-002: DPI Evasion — Deferred Scope

## Status

Deferred (config surface exists; runtime not implemented)

## Context

The configuration includes `safety.dpi_evasion` and `safety.dpi_evasion_consent` flags. These are parsed, validated as a paired consent gate, and stored in the `SafetySettings` struct (`internal/config/config.go`). However, **no runtime code** in `internal/tunnel/`, `internal/proxy/`, or `internal/cli/` performs any DPI evasion logic.

DPI evasion techniques — such as packet fragmentation, TLS fingerprint jitter, or protocol obfuscation — involve deep packet manipulation with significant complexity, legal ambiguity across jurisdictions, and potential to break legitimate traffic.

## Decision

**Do not implement DPI evasion in this version.** The config flags remain in place to:

1. Preserve backward compatibility for users and tooling that reference the config surface.
2. Document intent: the project acknowledges DPI evasion as a desired capability.
3. Block invalid configurations early: if a user enables `dpi_evasion` today, config validation returns an error stating the feature is not implemented. This prevents accidental reliance on non-functional flags.

### Alternatives considered

| Alternative | Rejected because |
| ----------- | ---------------- |
| Implement packet fragmentation / TLS jitter | Unbounded complexity; legal risk across jurisdictions; no clear scope boundary |
| Remove config flags | Breaks users and tooling that reference them; loses documented intent |
| Silently accept `dpi_evasion = true` without validation | Would mislead users into thinking the feature works; silent acceptance was an earlier interim approach since replaced by explicit rejection |

## Consequences

- Config validation rejects `dpi_evasion = true` with a clear "not implemented" message until DPI evasion is actually implemented.
- No runtime behavior changes. Users should not expect DPI evasion functionality.
- When and if DPI evasion is implemented, it should be gated behind the existing paired consent flags and accompanied by a dedicated ADR describing the specific techniques, risks, and scope.
