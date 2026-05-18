package tui

import "strings"

// spinnerFrames is the canonical Braille spinner used for any
// in-progress activity. The Braille glyphs render reliably across
// modern terminals and avoid relying on emoji width.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// spinnerFrame returns the spinner character at the given index.
// It tolerates negative or out-of-range indexes so callers can pass
// a freely-incrementing tick counter without bookkeeping.
func spinnerFrame(index int) string {
	if len(spinnerFrames) == 0 {
		return ""
	}
	if index < 0 {
		index = -index
	}
	return spinnerFrames[index%len(spinnerFrames)]
}

// progressEntry tracks the state of one async action that the
// surrounding application is running on behalf of the user.
type progressEntry struct {
	Action string
	State  string
	Detail string
}

// applyProgress merges a ProgressMsg into the in-progress list.
// "complete" or "failed" states remove the entry; running states
// upsert it. Empty actions are ignored so malformed messages cannot
// pollute the UI.
func applyProgress(entries []progressEntry, msg ProgressMsg) []progressEntry {
	action := strings.TrimSpace(msg.Action)
	if action == "" {
		return entries
	}
	state := strings.ToLower(strings.TrimSpace(msg.State))
	if state == "" {
		state = "running"
	}
	out := make([]progressEntry, 0, len(entries)+1)
	replaced := false
	for _, entry := range entries {
		if strings.EqualFold(entry.Action, action) {
			replaced = true
			if state == "complete" || state == "failed" {
				continue
			}
			out = append(out, progressEntry{
				Action: action,
				State:  state,
				Detail: strings.TrimSpace(msg.Detail),
			})
			continue
		}
		out = append(out, entry)
	}
	if !replaced && state != "complete" && state != "failed" {
		out = append(out, progressEntry{
			Action: action,
			State:  state,
			Detail: strings.TrimSpace(msg.Detail),
		})
	}
	return out
}
