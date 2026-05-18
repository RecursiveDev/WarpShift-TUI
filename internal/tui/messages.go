package tui

import "time"

// RefreshTickMsg is delivered by the periodic refresh ticker.
//
// It is purely a local event: the message itself never performs
// network I/O. State refreshers (RefreshSource) decide what, if
// anything, to recompute. Tests inject their own ticker so behavior
// is fully deterministic.
type RefreshTickMsg struct {
	// At is the time the tick fired.
	At time.Time
	// Sequence increments on each tick; useful for spinner frames
	// and for assertions in tests.
	Sequence int
}

// SnapshotMsg replaces the model's current state snapshot.
//
// It is the only sanctioned way to push new data (status, endpoints,
// notifications) into the running TUI from outside the model.
type SnapshotMsg struct {
	Snapshot Snapshot
}

// ProgressMsg announces the lifecycle of an asynchronous action that
// the surrounding application is performing on behalf of the user.
//
// The TUI uses these messages only to render visual feedback
// (spinner, busy list, toast). It never starts the action itself.
type ProgressMsg struct {
	// Action is a short human-readable identifier (for example
	// "endpoint scan", "config validate", "wireguard export").
	Action string
	// State is one of "started", "running", "complete", or "failed".
	State string
	// Detail is an optional human-readable detail string for the UI.
	// It must never contain credentials or secrets.
	Detail string
}
