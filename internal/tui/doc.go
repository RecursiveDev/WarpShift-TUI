// Package tui implements the safe local Bubble Tea terminal dashboard.
//
// The model in this package is intentionally pure relative to the
// network: it never performs live probes, account API calls, or
// tunnel I/O. All dynamic data arrives via injected dependencies:
//
//   - WithRefreshSource installs a pure local Snapshot supplier that
//     reads already-collected state and is invoked on each refresh
//     tick. Tests substitute deterministic fakes.
//   - WithRefreshInterval and WithTicker control how often (and via
//     which command primitive) refresh ticks fire. The default ticker
//     is bubbletea's Tick; tests inject fakeTicker.
//   - WithClock controls the time source used for spinner frames and
//     debounced text input.
//
// External producers of state push updates by sending SnapshotMsg or
// ProgressMsg into the running tea.Program. The model never starts an
// async action itself; it only renders the visual feedback for one.
//
// The TUI uses Bubble Tea v1 and Lipgloss v1 to preserve the current
// Model/Cmd contract and avoid a runtime migration in this release.
package tui
