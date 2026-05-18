package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// fakeTicker is an injectable replacement for tea.Tick. Each scheduled
// tick is buffered and only fires when the test calls Drive, so refresh
// behavior can be exercised without touching the real clock.
type fakeTicker struct {
	pending []func(time.Time) tea.Msg
}

func (f *fakeTicker) Tick(d time.Duration, fn func(time.Time) tea.Msg) tea.Cmd {
	return func() tea.Msg {
		f.pending = append(f.pending, fn)
		return nil
	}
}

// drive runs the most recently scheduled tick callback at fakeNow and
// returns the resulting message. It panics if nothing is pending so a
// test failure points directly at the missing scheduling.
func (f *fakeTicker) drive(now time.Time) tea.Msg {
	if len(f.pending) == 0 {
		panic("fakeTicker: no pending tick to drive")
	}
	fn := f.pending[len(f.pending)-1]
	f.pending = f.pending[:len(f.pending)-1]
	return fn(now)
}

func TestRefreshTickAppliesInjectedSourceAndReschedules(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	calls := 0
	source := func() Snapshot {
		calls++
		return Snapshot{
			Status: StatusSnapshot{
				WARP:    "on",
				Proxy:   "enabled",
				Message: "refreshed via injected source",
			},
			Endpoints: []EndpointSnapshot{
				{Address: "162.159.193.20:2408/udp", Healthy: true, RTT: 12 * time.Millisecond},
			},
		}
	}

	ticker := &fakeTicker{}
	model := NewModel(Snapshot{},
		WithRefreshSource(source),
		WithRefreshInterval(250*time.Millisecond),
		WithTicker(ticker.Tick),
		WithClock(clock),
	)

	cmd := model.Init()
	if cmd == nil {
		t.Fatal("Init returned nil command; expected a refresh tick to be scheduled")
	}
	if msg := cmd(); msg != nil {
		t.Fatalf("scheduled tick command returned %v, want nil", msg)
	}
	if len(ticker.pending) != 1 {
		t.Fatalf("ticker pending = %d, want 1", len(ticker.pending))
	}

	updated, nextCmd := model.Update(ticker.drive(now))
	model = updated.(Model)
	if calls != 1 {
		t.Fatalf("refresh source calls = %d, want 1", calls)
	}
	if nextCmd == nil {
		t.Fatal("after tick, Update returned no command; expected a follow-up tick")
	}
	if msg := nextCmd(); msg != nil {
		t.Fatalf("follow-up tick command returned %v, want nil", msg)
	}
	if len(ticker.pending) != 1 {
		t.Fatalf("after reschedule ticker pending = %d, want 1", len(ticker.pending))
	}

	view := model.View()
	for _, want := range []string{"WARP: on", "Proxy: enabled", "refreshed via injected source", "162.159.193.20:2408/udp"} {
		if !strings.Contains(view, want) {
			t.Fatalf("post-refresh view missing %q in:\n%s", want, view)
		}
	}
}

func TestRefreshDisabledWhenIntervalNonPositive(t *testing.T) {
	source := func() Snapshot { return Snapshot{} }
	model := NewModel(Snapshot{}, WithRefreshSource(source))
	if cmd := model.Init(); cmd != nil {
		t.Fatalf("Init returned a command when refresh is disabled: %v", cmd)
	}
}

func TestSnapshotMsgMergesIncomingState(t *testing.T) {
	model := NewModel(Snapshot{
		Status: StatusSnapshot{WARP: "off", Proxy: "disabled", Message: "initial"},
	})
	updated, _ := model.Update(SnapshotMsg{Snapshot: Snapshot{
		Status: StatusSnapshot{WARP: "on"},
		Endpoints: []EndpointSnapshot{
			{Address: "162.159.192.10:2408/udp", Healthy: false, Error: "timeout"},
		},
	}})
	view := updated.(Model).View()
	for _, want := range []string{"WARP: on", "Proxy: disabled", "162.159.192.10:2408/udp", "timeout"} {
		if !strings.Contains(view, want) {
			t.Fatalf("merged view missing %q in:\n%s", want, view)
		}
	}
	if !strings.Contains(view, "initial") {
		t.Fatalf("merged view dropped retained message in:\n%s", view)
	}
}

func TestProgressMsgRendersSpinnerAndCompletionToast(t *testing.T) {
	model := NewModel(Snapshot{}, WithClock(func() time.Time { return time.Unix(0, 0) }))
	updated, _ := model.Update(ProgressMsg{Action: "endpoint scan", State: "running", Detail: "probing static endpoints"})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	model = updated.(Model)
	view := model.View()
	for _, want := range []string{"Activity", "endpoint scan", "running", "probing static endpoints"} {
		if !strings.Contains(view, want) {
			t.Fatalf("activity tab missing %q in:\n%s", want, view)
		}
	}

	updated, _ = model.Update(ProgressMsg{Action: "endpoint scan", State: "complete"})
	model = updated.(Model)
	view = model.View()
	if strings.Contains(view, "endpoint scan — running") {
		t.Fatalf("completed action still rendered as running:\n%s", view)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	model = updated.(Model)
	view = model.View()
	if !strings.Contains(view, "endpoint scan complete") {
		t.Fatalf("dashboard missing completion toast in:\n%s", view)
	}
}

func TestProgressMsgFailureSurfacesErrorToast(t *testing.T) {
	model := NewModel(Snapshot{})
	updated, _ := model.Update(ProgressMsg{Action: "wireguard export", State: "failed", Detail: "missing identity"})
	view := updated.(Model).View()
	if !strings.Contains(view, "wireguard export failed: missing identity") {
		t.Fatalf("failure toast missing in:\n%s", view)
	}
}

func TestTabNavigationCyclesAndShowsHelpTab(t *testing.T) {
	model := NewModel(Snapshot{
		Endpoints: []EndpointSnapshot{
			{Address: "162.159.193.20:2408/udp", Healthy: true, RTT: 5 * time.Millisecond},
		},
	})
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	endpointView := updated.(Model).View()
	if !strings.Contains(endpointView, "162.159.193.20:2408/udp") {
		t.Fatalf("endpoints tab missing endpoint row:\n%s", endpointView)
	}

	updated, _ = updated.(Model).Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	helpView := updated.(Model).View()
	for _, want := range []string{"Help", "manual identity import remains available as a consent-free local path", "tab/1..4"} {
		if !strings.Contains(helpView, want) {
			t.Fatalf("help view missing %q in:\n%s", want, helpView)
		}
	}

	updated, _ = updated.(Model).Update(tea.KeyMsg{Type: tea.KeyTab})
	wrapped := updated.(Model).View()
	if !strings.Contains(wrapped, "Dashboard") {
		t.Fatalf("tab wrap-around did not return to dashboard:\n%s", wrapped)
	}
}

func TestPaletteTextInputSupportsBackspaceAndCursor(t *testing.T) {
	model := NewModel(Snapshot{})
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("proxy")})
	model = updated.(Model)
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	model = updated.(Model)
	view := model.View()
	if !strings.Contains(view, "query: prox") {
		t.Fatalf("palette query not updated by backspace:\n%s", view)
	}
	updated, _ = model.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	view = updated.(Model).View()
	if !strings.Contains(view, "query: \n") && !strings.Contains(view, "query:  ") && !strings.HasSuffix(strings.SplitN(strings.TrimSpace(view), "\n", 5)[1], "query:") {
		// Accept either trailing-space or empty rendering of the cleared query.
	}
	if strings.Contains(view, "query: prox") {
		t.Fatalf("ctrl+u did not clear palette query:\n%s", view)
	}
}

func TestManualRefreshKeyAppliesInjectedSnapshotImmediately(t *testing.T) {
	state := Snapshot{Status: StatusSnapshot{WARP: "on", Proxy: "enabled", Message: "manual refresh"}}
	source := func() Snapshot { return state }
	model := NewModel(Snapshot{}, WithRefreshSource(source))

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	view := updated.(Model).View()
	for _, want := range []string{"WARP: on", "Proxy: enabled", "manual refresh"} {
		if !strings.Contains(view, want) {
			t.Fatalf("manual refresh did not apply %q in:\n%s", want, view)
		}
	}
}

func TestFocusBlurMessagesUpdateWindowState(t *testing.T) {
	model := NewModel(Snapshot{})
	updated, _ := model.Update(tea.BlurMsg{})
	model = updated.(Model)
	if !strings.Contains(model.View(), "window blurred") {
		t.Fatalf("blur indicator missing in:\n%s", model.View())
	}
	updated, _ = model.Update(tea.FocusMsg{})
	model = updated.(Model)
	if strings.Contains(model.View(), "window blurred") {
		t.Fatalf("focus did not clear blur indicator:\n%s", model.View())
	}
}

func TestTextInputDebouncePending(t *testing.T) {
	now := time.Unix(0, 0)
	input := newTextInput("placeholder")
	input.debounce = 50 * time.Millisecond
	input, _ = input.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("ab")}, now)
	if v, ok := input.Pending(now); ok || v == "ab" {
		t.Fatalf("input emitted before debounce: ok=%v value=%q", ok, v)
	}
	if v, ok := input.Pending(now.Add(60 * time.Millisecond)); !ok || v != "ab" {
		t.Fatalf("input did not emit after debounce: ok=%v value=%q", ok, v)
	}
	if v, ok := input.Pending(now.Add(80 * time.Millisecond)); ok {
		t.Fatalf("input re-emitted with no further changes: ok=%v value=%q", ok, v)
	}
}
