# ADR-004: Bubble Tea v2 Migration — Deferred

## Status

Deferred (Bubble Tea v1 is current; v2 migration is an infrastructure change)

## Context

WarpShift-TUI uses Bubble Tea v1.3.10 (`github.com/charmbracelet/bubbletea v1.3.10` in `go.mod`). The Bubble Tea ecosystem has a v2 release that introduces breaking changes to the `Model` interface, `tea.Cmd` return types, and message handling.

The TUI model (`internal/tui/model.go`) implements the v1 `Model` interface with `Init()`, `Update()`, and `View()` methods. The project also depends on Lipgloss v1.1.0 for styling.

## Decision

**Do not migrate to Bubble Tea v2 at this time.** Continue using v1.3.10.

### Rationale

- **v1 is stable and functional.** The TUI dashboard works correctly on v1 with no known issues.
- **v2 is a breaking change.** Migration requires rewriting every `Model`, `Update`, and `View` method, plus adapting all `tea.Cmd` and `tea.Msg` patterns. This is a non-trivial refactor with no user-facing benefit.
- **Lipgloss compatibility.** Lipgloss v1 is compatible with Bubble Tea v1. v2 may require Lipgloss updates as well.
- **Scope separation.** Infrastructure migrations should not be mixed with feature work. A dedicated v2 migration phase avoids conflating UI logic changes with framework migration bugs.

### Migration path (when approved)

1. Create a dedicated branch for v2 migration.
2. Update `go.mod` to Bubble Tea v2.
3. Adapt `internal/tui/model.go` to the new `Model` interface.
4. Update all `tea.Cmd` and `tea.Msg` patterns.
5. Verify Lipgloss compatibility and update if needed.
6. Run the full test suite (`make test`) and verify TUI behavior manually.
7. Merge only after TUI is fully functional on v2.

## Consequences

- The TUI continues to use Bubble Tea v1.3.10.
- No v2-specific features (if any) are available.
- When v2 migration is approved, it should be an infrastructure-only change with no concurrent feature work.
