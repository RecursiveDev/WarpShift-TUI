package tui

import "github.com/charmbracelet/lipgloss"

// theme centralizes the colors, borders, and spacing tokens used by
// the TUI. It is intentionally conservative: every style degrades
// gracefully on terminals that do not support truecolor or italics.
//
// The palette is anchored on a subdued indigo accent so the dashboard
// stays readable on both light and dark terminal backgrounds without
// shipping high-saturation reds, which the safety guidelines forbid
// for primary controls.
type theme struct {
	Title        lipgloss.Style
	Subtitle     lipgloss.Style
	Panel        lipgloss.Style
	PanelActive  lipgloss.Style
	Muted        lipgloss.Style
	Footer       lipgloss.Style
	Healthy      lipgloss.Style
	Unhealthy    lipgloss.Style
	Warning      lipgloss.Style
	Info         lipgloss.Style
	Error        lipgloss.Style
	Action       lipgloss.Style
	Spinner      lipgloss.Style
	TabActive    lipgloss.Style
	TabInactive  lipgloss.Style
	TabSeparator lipgloss.Style
	Cursor       lipgloss.Style
}

// defaultTheme returns the production theme used by the TUI. It is
// computed once and shared across all rendering paths so individual
// components stay cheap to render.
func defaultTheme() theme {
	accent := lipgloss.Color("#8ab4f8")     // soft indigo
	accentDim := lipgloss.Color("#6f8ec7")  // muted accent
	healthy := lipgloss.Color("#7bd88f")    // calm green
	warning := lipgloss.Color("#f5c451")    // warm amber
	danger := lipgloss.Color("#e0707a")     // accessible coral, not pure red
	muted := lipgloss.Color("#8a8a8a")      // mid-gray
	subtle := lipgloss.Color("#5f5f5f")     // border gray
	highlight := lipgloss.Color("#1f2733")  // panel background highlight
	background := lipgloss.Color("#0f1115") // app background

	border := lipgloss.RoundedBorder()

	return theme{
		Title: lipgloss.NewStyle().
			Bold(true).
			Foreground(accent).
			Padding(0, 1),
		Subtitle: lipgloss.NewStyle().
			Foreground(accentDim).
			Padding(0, 1),
		Panel: lipgloss.NewStyle().
			Border(border).
			BorderForeground(subtle).
			Padding(0, 1),
		PanelActive: lipgloss.NewStyle().
			Border(border).
			BorderForeground(accent).
			Padding(0, 1),
		Muted: lipgloss.NewStyle().
			Foreground(muted).
			Faint(true),
		Footer: lipgloss.NewStyle().
			Foreground(muted).
			Faint(true),
		Healthy: lipgloss.NewStyle().
			Foreground(healthy).
			Bold(true),
		Unhealthy: lipgloss.NewStyle().
			Foreground(danger).
			Bold(true),
		Warning: lipgloss.NewStyle().
			Foreground(warning).
			Bold(true),
		Info: lipgloss.NewStyle().
			Foreground(accent),
		Error: lipgloss.NewStyle().
			Foreground(danger).
			Bold(true),
		Action: lipgloss.NewStyle().
			Foreground(accent).
			Italic(true),
		Spinner: lipgloss.NewStyle().
			Foreground(accent).
			Bold(true),
		TabActive: lipgloss.NewStyle().
			Foreground(background).
			Background(accent).
			Bold(true).
			Padding(0, 1),
		TabInactive: lipgloss.NewStyle().
			Foreground(muted).
			Background(highlight).
			Padding(0, 1),
		TabSeparator: lipgloss.NewStyle().
			Foreground(subtle),
		Cursor: lipgloss.NewStyle().
			Foreground(background).
			Background(accent),
	}
}
