package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

func TestModelRendersDashboardStatusEndpointsFooterAndHelp(t *testing.T) {
	model := NewModel(Snapshot{
		AppName: "WarpShift-TUI",
		Version: "dev",
		Status: StatusSnapshot{
			WARP:    "off",
			Proxy:   "disabled",
			Message: "manual identity not imported",
		},
		Endpoints: []EndpointSnapshot{
			{Address: "162.159.193.20:2408/udp", Healthy: true, RTT: 15 * time.Millisecond},
			{Address: "162.159.192.10:2408/udp", Healthy: false, Error: "probe disabled"},
		},
	})

	view := model.View()
	for _, want := range []string{
		"WarpShift-TUI",
		"Dashboard",
		"Status",
		"WARP: off",
		"Proxy: disabled",
		"manual identity not imported",
		"Endpoints",
		"162.159.193.20:2408/udp",
		"15ms",
		"probe disabled",
		"?: help",
		"q: quit",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("dashboard view missing %q in:\n%s", want, view)
		}
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	helpModel, ok := updated.(Model)
	if !ok {
		t.Fatalf("updated model type = %T, want tui.Model", updated)
	}
	help := helpModel.View()
	for _, want := range []string{
		"Help",
		"manual identity import only",
		"localhost proxy defaults",
		"authentication required for remote proxy binds",
		"no account registration",
		"no WARP+ generation",
		"no DPI evasion",
		"no streaming unlock",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help view missing %q in:\n%s", want, help)
		}
	}
}

func TestModelRendersPolishedUXComponentsAndCommandPalette(t *testing.T) {
	model := NewModel(Snapshot{
		Status: StatusSnapshot{
			WARP:    "on",
			Proxy:   "enabled",
			Message: "using cached endpoint status",
		},
		Endpoints: []EndpointSnapshot{
			{Address: "162.159.193.20:2408/udp", Healthy: true, RTT: 15 * time.Millisecond},
		},
		Notifications: []NotificationSnapshot{
			{Level: "warning", Message: "identity file permissions should be 0600"},
		},
	})

	view := model.View()
	for _, want := range []string{
		"Address",
		"Health",
		"Detail",
		"Context Help",
		"Toast",
		"WARNING",
		"identity file permissions should be 0600",
		"/: command palette",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("dashboard UX view missing %q in:\n%s", want, view)
		}
	}

	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	paletteModel, ok := updated.(Model)
	if !ok {
		t.Fatalf("updated model type = %T, want tui.Model", updated)
	}
	updated, _ = paletteModel.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p', 'r', 'o', 'x'}})
	paletteModel = updated.(Model)
	palette := paletteModel.View()
	for _, want := range []string{
		"Command Palette",
		"query: prox",
		"proxy validate",
	} {
		if !strings.Contains(palette, want) {
			t.Fatalf("command palette missing %q in:\n%s", want, palette)
		}
	}
	if strings.Contains(palette, "wireguard export") {
		t.Fatalf("command palette did not filter unrelated commands:\n%s", palette)
	}
}

func TestModelInteractiveIdentitySetupMasksPrivateKeyAndShowsValidationPreview(t *testing.T) {
	model := NewModel(Snapshot{})
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'i'}})
	setupModel := updated.(Model)

	setupModel = typeIntoIdentityField(t, setupModel, "manual-device")
	setupModel = tabIdentityField(t, setupModel)
	setupModel = typeIntoIdentityField(t, setupModel, "super-private-key")
	setupModel = tabIdentityField(t, setupModel)
	setupModel = typeIntoIdentityField(t, setupModel, "172.16.0.2/32")
	setupModel = tabIdentityField(t, setupModel)
	setupModel = typeIntoIdentityField(t, setupModel, "peer-public-key")
	setupModel = tabIdentityField(t, setupModel)
	setupModel = typeIntoIdentityField(t, setupModel, "engage.cloudflareclient.com:2408")

	view := setupModel.View()
	for _, want := range []string{
		"Interactive Identity Setup",
		"Private Key",
		"••••",
		"Validation preview",
		"ready to import",
		"no account/API calls",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("identity setup view missing %q in:\n%s", want, view)
		}
	}
	if strings.Contains(view, "super-private-key") {
		t.Fatalf("identity setup view echoed private key material:\n%s", view)
	}
}

func TestCommandPaletteQueuesDeterministicActionIntent(t *testing.T) {
	model := NewModel(Snapshot{})
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	paletteModel := updated.(Model)
	view := paletteModel.View()
	for _, want := range []string{"endpoint scan now", "status refresh", "wireguard export"} {
		if !strings.Contains(view, want) {
			t.Fatalf("command palette missing action %q in:\n%s", want, view)
		}
	}
	paletteModel = typePaletteQuery(t, paletteModel, "scan now")

	updated, _ = paletteModel.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model = updated.(Model)
	view = model.View()
	if !strings.Contains(view, "ACTION: endpoint scan-now requested; waiting for injected scanner") {
		t.Fatalf("dashboard missing deterministic scan-now action toast in:\n%s", view)
	}
}

func typeIntoIdentityField(t *testing.T, model Model, value string) Model {
	t.Helper()
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)})
	return updated.(Model)
}

func tabIdentityField(t *testing.T, model Model) Model {
	t.Helper()
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyTab})
	return updated.(Model)
}

func typePaletteQuery(t *testing.T, model Model, value string) Model {
	t.Helper()
	updated, _ := model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)})
	return updated.(Model)
}
