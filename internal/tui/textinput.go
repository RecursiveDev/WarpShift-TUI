package tui

import (
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
)

// textInput is a minimal, dependency-free text input primitive that
// matches the patterns popularized by github.com/charmbracelet/bubbles
// without pulling in another dependency. It supports masking for
// secret material, simple debouncing, and word-aware deletion.
type textInput struct {
	value          string
	placeholder    string
	cursor         int
	masked         bool
	focused        bool
	maxLen         int
	debounce       time.Duration
	lastChangeAt   time.Time
	lastEmittedAt  time.Time
	lastEmitted    string
	pendingPending bool
}

// newTextInput returns a text input prepared with sane defaults.
// callers can set Placeholder, Masked, or MaxLen on the returned value
// before mounting it on a model.
func newTextInput(placeholder string) textInput {
	return textInput{
		placeholder: placeholder,
		maxLen:      512,
		debounce:    120 * time.Millisecond,
	}
}

// Focus marks the input as focused so View renders the cursor.
func (t *textInput) Focus() { t.focused = true }

// Blur removes focus.
func (t *textInput) Blur() { t.focused = false }

// SetValue replaces the text and snaps the cursor to the end.
func (t *textInput) SetValue(v string) {
	t.value = v
	t.cursor = len([]rune(v))
}

// Value returns the current text.
func (t textInput) Value() string { return t.value }

// Reset clears the text, cursor, and debounce state.
func (t *textInput) Reset() {
	t.value = ""
	t.cursor = 0
	t.lastChangeAt = time.Time{}
	t.lastEmittedAt = time.Time{}
	t.lastEmitted = ""
	t.pendingPending = false
}

// Update processes a key event and returns the updated input. It
// reports whether the value changed so callers can drive their own
// commands (search, filter) without re-allocating commands per key.
func (t textInput) Update(msg tea.KeyMsg, now time.Time) (textInput, bool) {
	previous := t.value
	switch msg.Type {
	case tea.KeyBackspace:
		if t.cursor > 0 {
			runes := []rune(t.value)
			t.value = string(runes[:t.cursor-1]) + string(runes[t.cursor:])
			t.cursor--
		}
	case tea.KeyDelete:
		runes := []rune(t.value)
		if t.cursor < len(runes) {
			t.value = string(runes[:t.cursor]) + string(runes[t.cursor+1:])
		}
	case tea.KeyLeft:
		if t.cursor > 0 {
			t.cursor--
		}
	case tea.KeyRight:
		runes := []rune(t.value)
		if t.cursor < len(runes) {
			t.cursor++
		}
	case tea.KeyHome, tea.KeyCtrlA:
		t.cursor = 0
	case tea.KeyEnd, tea.KeyCtrlE:
		t.cursor = len([]rune(t.value))
	case tea.KeyCtrlU:
		t.value = ""
		t.cursor = 0
	case tea.KeyCtrlW:
		t.value, t.cursor = deleteWordBackward(t.value, t.cursor)
	case tea.KeyRunes, tea.KeySpace:
		runes := msg.Runes
		if msg.Type == tea.KeySpace {
			runes = []rune{' '}
		}
		t.value, t.cursor = insertRunes(t.value, t.cursor, runes, t.maxLen)
	default:
		return t, false
	}
	if t.value != previous {
		t.lastChangeAt = now
		t.pendingPending = true
	}
	return t, t.value != previous
}

// Pending reports whether the input has unemitted changes that should
// remain debounced. It returns the new value and true once enough
// quiet time has passed; otherwise it returns the prior emitted value
// and false. This allows a host model to wait for a steady state
// before kicking off expensive work like filtering large lists.
func (t *textInput) Pending(now time.Time) (string, bool) {
	if !t.pendingPending {
		return t.lastEmitted, false
	}
	if t.debounce <= 0 || now.Sub(t.lastChangeAt) >= t.debounce {
		t.pendingPending = false
		t.lastEmitted = t.value
		t.lastEmittedAt = now
		return t.value, true
	}
	return t.lastEmitted, false
}

// View renders the input. When focused and unmasked it includes a
// block cursor at the current insertion point. Masked inputs render
// only a count of bullets so secret material is never echoed.
func (t textInput) View(th theme) string {
	if t.masked {
		if t.value == "" {
			if t.placeholder != "" {
				return th.Muted.Render(t.placeholder)
			}
			return th.Muted.Render("hidden input empty")
		}
		return strings.Repeat("•", min(len([]rune(t.value)), 12)) + " (hidden)"
	}
	if t.value == "" && !t.focused {
		if t.placeholder != "" {
			return th.Muted.Render(t.placeholder)
		}
		return th.Muted.Render("empty")
	}
	if !t.focused {
		return t.value
	}
	runes := []rune(t.value)
	cursor := t.cursor
	if cursor > len(runes) {
		cursor = len(runes)
	}
	var b strings.Builder
	b.WriteString(string(runes[:cursor]))
	if cursor == len(runes) {
		b.WriteString(th.Cursor.Render(" "))
	} else {
		b.WriteString(th.Cursor.Render(string(runes[cursor])))
		b.WriteString(string(runes[cursor+1:]))
	}
	return b.String()
}

func insertRunes(value string, cursor int, runes []rune, maxLen int) (string, int) {
	if len(runes) == 0 {
		return value, cursor
	}
	current := []rune(value)
	if cursor < 0 {
		cursor = 0
	}
	if cursor > len(current) {
		cursor = len(current)
	}
	allowed := runes
	if maxLen > 0 && len(current)+len(runes) > maxLen {
		room := maxLen - len(current)
		if room <= 0 {
			return value, cursor
		}
		allowed = runes[:room]
	}
	out := make([]rune, 0, len(current)+len(allowed))
	out = append(out, current[:cursor]...)
	out = append(out, allowed...)
	out = append(out, current[cursor:]...)
	return string(out), cursor + len(allowed)
}

func deleteWordBackward(value string, cursor int) (string, int) {
	if cursor == 0 {
		return value, cursor
	}
	runes := []rune(value)
	if cursor > len(runes) {
		cursor = len(runes)
	}
	end := cursor
	// skip trailing spaces
	for end > 0 && unicode.IsSpace(runes[end-1]) {
		end--
	}
	for end > 0 && !unicode.IsSpace(runes[end-1]) {
		end--
	}
	out := append([]rune{}, runes[:end]...)
	out = append(out, runes[cursor:]...)
	return string(out), end
}
