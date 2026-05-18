package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Snapshot is a fully local, already-collected view of application state.
type Snapshot struct {
	AppName       string
	Version       string
	Status        StatusSnapshot
	Endpoints     []EndpointSnapshot
	Notifications []NotificationSnapshot
}

// StatusSnapshot contains local status text rendered by the TUI.
type StatusSnapshot struct {
	WARP    string
	Proxy   string
	Message string
}

// EndpointSnapshot contains endpoint row data that was collected outside the TUI.
type EndpointSnapshot struct {
	Address string
	Healthy bool
	RTT     time.Duration
	Error   string
}

// NotificationSnapshot contains non-secret status/toast text rendered by the TUI.
type NotificationSnapshot struct {
	Level   string
	Message string
}

// Model is the Bubble Tea shell model for the safe local dashboard.
type Model struct {
	snapshot      Snapshot
	showHelp      bool
	showPalette   bool
	showIdentity  bool
	paletteQuery  string
	identitySetup identitySetupState
	width         int
}

type paletteEntry struct {
	Name          string
	Description   string
	ActionMessage string
}

type identitySetupState struct {
	active             int
	deviceID           string
	privateKey         string
	interfaceAddresses string
	peerPublicKey      string
	endpoint           string
	dns                string
}

const identitySetupFieldCount = 6

var (
	titleStyle  = lipgloss.NewStyle().Bold(true).Padding(0, 1)
	panelStyle  = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
	mutedStyle  = lipgloss.NewStyle().Faint(true)
	footerStyle = lipgloss.NewStyle().Faint(true)
)

// NewModel creates a TUI model from injected/static state only.
func NewModel(snapshot Snapshot) Model {
	if strings.TrimSpace(snapshot.AppName) == "" {
		snapshot.AppName = "WarpShift-TUI"
	}
	if strings.TrimSpace(snapshot.Version) == "" {
		snapshot.Version = "dev"
	}
	if strings.TrimSpace(snapshot.Status.WARP) == "" {
		snapshot.Status.WARP = "unknown"
	}
	if strings.TrimSpace(snapshot.Status.Proxy) == "" {
		snapshot.Status.Proxy = "disabled"
	}
	if strings.TrimSpace(snapshot.Status.Message) == "" {
		snapshot.Status.Message = "local dashboard; live network workflows require explicit user action"
	}
	return Model{snapshot: snapshot}
}

// Init performs no side effects; state is injected before the model is created.
func (m Model) Init() tea.Cmd { return nil }

// Update handles local keyboard/window events only.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showIdentity {
			return m.updateIdentitySetup(msg), nil
		}
		if m.showPalette {
			return m.updatePalette(msg), nil
		}
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?", "h":
			m.showHelp = !m.showHelp
			return m, nil
		case "/":
			m.showHelp = false
			m.showPalette = true
			m.paletteQuery = ""
			return m, nil
		case "i":
			m.showHelp = false
			m.showIdentity = true
			return m, nil
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
	}
	return m, nil
}

func (m Model) updatePalette(msg tea.KeyMsg) Model {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.showPalette = false
		m.paletteQuery = ""
	case "enter":
		m.applyPaletteAction()
		m.showPalette = false
	case "backspace":
		m.paletteQuery = trimLastRune(m.paletteQuery)
	default:
		if len(msg.Runes) > 0 {
			m.paletteQuery += string(msg.Runes)
		}
	}
	return m
}

func (m Model) updateIdentitySetup(msg tea.KeyMsg) Model {
	switch msg.String() {
	case "esc", "ctrl+c":
		m.showIdentity = false
	case "tab", "enter":
		m.identitySetup.active = (m.identitySetup.active + 1) % identitySetupFieldCount
	case "shift+tab", "backtab":
		m.identitySetup.active = (m.identitySetup.active + identitySetupFieldCount - 1) % identitySetupFieldCount
	case "backspace":
		m.setIdentityField(trimLastRune(m.identityFieldValue()))
	default:
		if len(msg.Runes) > 0 {
			m.setIdentityField(m.identityFieldValue() + string(msg.Runes))
		}
	}
	return m
}

func (m *Model) applyPaletteAction() {
	entry, ok := m.selectedPaletteEntry()
	if !ok {
		return
	}
	if entry.Name == "identity setup" {
		m.showIdentity = true
	}
	if strings.TrimSpace(entry.ActionMessage) != "" {
		m.appendNotification("action", entry.ActionMessage)
	}
}

func (m Model) selectedPaletteEntry() (paletteEntry, bool) {
	query := strings.ToLower(strings.TrimSpace(m.paletteQuery))
	for _, entry := range commandPaletteEntries() {
		search := strings.ToLower(entry.Name + " " + entry.Description)
		if query == "" || strings.Contains(search, query) {
			return entry, true
		}
	}
	return paletteEntry{}, false
}

func (m *Model) appendNotification(level, message string) {
	m.snapshot.Notifications = append(m.snapshot.Notifications, NotificationSnapshot{Level: level, Message: message})
}

// View renders either the dashboard, help screen, command palette, or identity setup screen.
func (m Model) View() string {
	if m.showPalette {
		return m.renderCommandPalette()
	}
	if m.showIdentity {
		return m.renderIdentitySetup()
	}
	if m.showHelp {
		return m.renderHelp()
	}
	return m.renderDashboard()
}

func (m Model) renderDashboard() string {
	header := titleStyle.Render(fmt.Sprintf("%s %s", m.snapshot.AppName, m.snapshot.Version))
	status := panelStyle.Render(strings.Join([]string{
		"Status",
		fmt.Sprintf("WARP: %s", m.snapshot.Status.WARP),
		fmt.Sprintf("Proxy: %s", m.snapshot.Status.Proxy),
		m.snapshot.Status.Message,
	}, "\n"))
	endpoints := panelStyle.Render("Endpoints\n" + m.endpointRows())
	contextHelp := panelStyle.Render(strings.Join([]string{
		"Context Help",
		"Use local fixtures and injected scans; live tunnel workflows require explicit command action.",
		"/: command palette • i: identity setup • ?: safety help • q: quit",
	}, "\n"))
	footer := footerStyle.Render("/: command palette • i: identity setup • ?: help • h: help • q: quit")
	sections := []string{header, "Dashboard", status, endpoints}
	if notifications := m.renderNotifications(); notifications != "" {
		sections = append(sections, notifications)
	}
	sections = append(sections, contextHelp, footer)
	return lipgloss.JoinVertical(lipgloss.Left, sections...) + "\n"
}

func (m Model) endpointRows() string {
	if len(m.snapshot.Endpoints) == 0 {
		return mutedStyle.Render("No endpoints available; use static/injected scan sources.")
	}
	rows := []string{fmt.Sprintf("%-30s  %-9s  %s", "Address", "Health", "Detail")}
	for _, endpoint := range m.snapshot.Endpoints {
		state := "unhealthy"
		detail := endpoint.Error
		if endpoint.Healthy {
			state = "healthy"
			detail = endpoint.RTT.String()
		}
		if detail == "" {
			detail = "not probed"
		}
		rows = append(rows, fmt.Sprintf("%-30s  %-9s  %s", endpoint.Address, state, detail))
	}
	return strings.Join(rows, "\n")
}

func (m Model) renderNotifications() string {
	rows := make([]string, 0, len(m.snapshot.Notifications)+1)
	for _, notification := range m.snapshot.Notifications {
		message := strings.TrimSpace(notification.Message)
		if message == "" {
			continue
		}
		level := strings.ToUpper(strings.TrimSpace(notification.Level))
		if level == "" {
			level = "INFO"
		}
		rows = append(rows, fmt.Sprintf("%s: %s", level, message))
	}
	if len(rows) == 0 {
		return ""
	}
	return panelStyle.Render("Toast\n" + strings.Join(rows, "\n"))
}

func (m Model) renderIdentitySetup() string {
	rows := []string{
		"Interactive Identity Setup",
		"Manual user-provided identity preview; account/API workflows require explicit command consent.",
		"Private key input is hidden and is never echoed.",
		"",
	}
	for index, field := range identitySetupFieldLabels() {
		marker := " "
		if index == m.identitySetup.active {
			marker = ">"
		}
		rows = append(rows, fmt.Sprintf("%s %s: %s", marker, field, m.renderIdentityField(index)))
	}
	rows = append(rows, "", m.identityValidationPreview(), "", "tab/enter: next field • backspace: edit • esc: close")
	return panelStyle.Render(strings.Join(rows, "\n")) + "\n"
}

func identitySetupFieldLabels() []string {
	return []string{"Device ID", "Private Key", "Interface Addresses", "Peer Public Key", "Endpoint", "DNS"}
}

func (m Model) renderIdentityField(index int) string {
	value := m.identityFieldValueAt(index)
	if index == 1 {
		if value == "" {
			return mutedStyle.Render("hidden input empty")
		}
		return "•••••• (hidden)"
	}
	if strings.TrimSpace(value) == "" {
		return mutedStyle.Render("empty")
	}
	return value
}

func (m Model) identityValidationPreview() string {
	_, err := warp.ImportManualIdentity(warp.ManualIdentity{
		DeviceID:           m.identitySetup.deviceID,
		PrivateKey:         m.identitySetup.privateKey,
		InterfaceAddresses: splitCSV(m.identitySetup.interfaceAddresses),
		PeerPublicKey:      m.identitySetup.peerPublicKey,
		Endpoint:           m.identitySetup.endpoint,
		DNS:                splitCSV(m.identitySetup.dns),
	})
	if err != nil {
		return "Validation preview: " + err.Error()
	}
	return "Validation preview: ready to import manually; account/API workflows require explicit command consent."
}

func (m Model) identityFieldValue() string {
	return m.identityFieldValueAt(m.identitySetup.active)
}

func (m Model) identityFieldValueAt(index int) string {
	switch index {
	case 0:
		return m.identitySetup.deviceID
	case 1:
		return m.identitySetup.privateKey
	case 2:
		return m.identitySetup.interfaceAddresses
	case 3:
		return m.identitySetup.peerPublicKey
	case 4:
		return m.identitySetup.endpoint
	case 5:
		return m.identitySetup.dns
	default:
		return ""
	}
}

func (m *Model) setIdentityField(value string) {
	switch m.identitySetup.active {
	case 0:
		m.identitySetup.deviceID = value
	case 1:
		m.identitySetup.privateKey = value
	case 2:
		m.identitySetup.interfaceAddresses = value
	case 3:
		m.identitySetup.peerPublicKey = value
	case 4:
		m.identitySetup.endpoint = value
	case 5:
		m.identitySetup.dns = value
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func trimLastRune(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	return string(runes[:len(runes)-1])
}

func (m Model) renderCommandPalette() string {
	query := strings.ToLower(strings.TrimSpace(m.paletteQuery))
	rows := []string{
		"Command Palette",
		fmt.Sprintf("query: %s", m.paletteQuery),
		"",
	}
	for _, entry := range commandPaletteEntries() {
		search := strings.ToLower(entry.Name + " " + entry.Description)
		if query != "" && !strings.Contains(search, query) {
			continue
		}
		rows = append(rows, fmt.Sprintf("- %s — %s", entry.Name, entry.Description))
	}
	if len(rows) == 3 {
		rows = append(rows, mutedStyle.Render("No matching local commands"))
	}
	rows = append(rows, "", "esc: close • enter: close • type to search")
	return panelStyle.Render(strings.Join(rows, "\n")) + "\n"
}

func commandPaletteEntries() []paletteEntry {
	return []paletteEntry{
		{Name: "config validate", Description: "validate local TOML settings"},
		{Name: "identity setup", Description: "open guided manual identity setup preview"},
		{Name: "identity import", Description: "import a manually supplied identity JSON"},
		{Name: "identity inspect", Description: "inspect identity metadata without printing keys"},
		{Name: "wireguard export", Description: "export a profile from stored manual identity", ActionMessage: "ACTION: wireguard export intent recorded; profile export requires explicit CLI confirmation"},
		{Name: "endpoint scan", Description: "scan static endpoints through an injected probe"},
		{Name: "endpoint scan now", Description: "request an immediate scan through the injected scanner", ActionMessage: "ACTION: endpoint scan-now requested; waiting for injected scanner"},
		{Name: "status refresh", Description: "request a local status snapshot refresh", ActionMessage: "ACTION: status refresh requested; waiting for injected status source"},
		{Name: "proxy validate", Description: "check proxy bind/auth configuration"},
		{Name: "proxy start", Description: "validate proxy start scaffold"},
	}
}

func (m Model) renderHelp() string {
	body := strings.Join([]string{
		"Help",
		"",
		"Keys:",
		"  /      open command palette",
		"  i      open guided manual identity setup preview",
		"  ? / h  toggle help",
		"  q      quit",
		"",
		"Safety boundaries:",
		"  - manual identity import remains available as a consent-free local path",
		"  - localhost proxy defaults",
		"  - authentication required for remote proxy binds",
		"  - account automation requires explicit user consent",
		"  - WARP+ workflows require explicit user consent",
		"  - DPI-related workflows require explicit user consent",
		"  - streaming/IP rotation workflows require explicit user consent",
	}, "\n")
	return panelStyle.Render(body) + "\n"
}

// Run starts the Bubble Tea program for a prepared snapshot.
func Run(ctx context.Context, snapshot Snapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := tea.NewProgram(NewModel(snapshot)).Run()
	if err != nil {
		return err
	}
	return ctx.Err()
}
