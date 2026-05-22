package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/RecursiveDev/WarpShift-TUI/internal/textutil"
	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const maxNotifications = 100

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

// RefreshSource produces a fresh Snapshot. It MUST be pure relative to
// the TUI: implementations are expected to read already-collected
// state (caches, channels, in-memory mirrors) and never perform live
// network calls inside the call. The tests in this package inject
// deterministic fakes.
type RefreshSource func() Snapshot

// TickerFunc returns a Bubble Tea command that emits a single message
// after the given duration. It mirrors the signature of tea.Tick so
// the default implementation is a thin pass-through, while tests can
// substitute a deterministic command.
type TickerFunc func(d time.Duration, fn func(time.Time) tea.Msg) tea.Cmd

// Option customizes Model dependencies for tests and integrations.
type Option func(*options)

type options struct {
	refresh         RefreshSource
	refreshInterval time.Duration
	ticker          TickerFunc
	clock           func() time.Time
}

// WithRefreshSource installs a pure local snapshot supplier that the
// TUI consults on every refresh tick.
func WithRefreshSource(src RefreshSource) Option {
	return func(o *options) {
		if src != nil {
			o.refresh = src
		}
	}
}

// WithRefreshInterval sets how often refresh ticks fire. Values <= 0
// disable the periodic refresh path entirely.
func WithRefreshInterval(d time.Duration) Option {
	return func(o *options) { o.refreshInterval = d }
}

// WithTicker overrides the default Bubble Tea ticker. Tests use this
// to drive ticks deterministically without involving the real clock.
func WithTicker(t TickerFunc) Option {
	return func(o *options) {
		if t != nil {
			o.ticker = t
		}
	}
}

// WithClock overrides the time source used for spinner frames and
// debouncing.
func WithClock(now func() time.Time) Option {
	return func(o *options) {
		if now != nil {
			o.clock = now
		}
	}
}

// Model is the Bubble Tea shell model for the safe local dashboard.
type Model struct {
	snapshot      Snapshot
	progress      []progressEntry
	showHelp      bool
	showPalette   bool
	showIdentity  bool
	palette       textInput
	identitySetup identitySetupState
	width         int
	height        int
	focused       bool
	activeTab     int
	tabs          []string

	refresh         RefreshSource
	refreshInterval time.Duration
	ticker          TickerFunc
	clock           func() time.Time

	tickSeq    int
	lastTickAt time.Time

	th theme
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

const (
	tabDashboard = iota
	tabEndpoints
	tabActivity
	tabHelp
)

// NewModel creates a TUI model from injected/static state only.
func NewModel(snapshot Snapshot, opts ...Option) Model {
	cfg := options{
		refreshInterval: 0,
		ticker:          tea.Tick,
		clock:           time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
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
	palette := newTextInput("type to search local commands")
	palette.maxLen = 256
	return Model{
		snapshot:        snapshot,
		palette:         palette,
		focused:         true,
		tabs:            []string{"Dashboard", "Endpoints", "Activity", "Help"},
		refresh:         cfg.refresh,
		refreshInterval: cfg.refreshInterval,
		ticker:          cfg.ticker,
		clock:           cfg.clock,
		th:              defaultTheme(),
	}
}

// Init schedules the first refresh tick if a refresh source is wired.
// It performs no I/O; the tick itself is what eventually drives a
// pure RefreshSource call from the application layer.
func (m Model) Init() tea.Cmd {
	if m.refresh == nil || m.refreshInterval <= 0 || m.ticker == nil {
		return nil
	}
	return m.scheduleRefreshTick()
}

func (m Model) scheduleRefreshTick() tea.Cmd {
	if m.ticker == nil || m.refreshInterval <= 0 {
		return nil
	}
	seq := m.tickSeq + 1
	return m.ticker(m.refreshInterval, func(t time.Time) tea.Msg {
		return RefreshTickMsg{At: t, Sequence: seq}
	})
}

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
		return m.updateDashboardKey(msg)
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tea.FocusMsg:
		m.focused = true
	case tea.BlurMsg:
		m.focused = false
	case RefreshTickMsg:
		m.tickSeq = msg.Sequence
		m.lastTickAt = msg.At
		var cmd tea.Cmd
		if m.refresh != nil {
			snap := m.refresh()
			m.snapshot = mergeSnapshot(m.snapshot, snap)
		}
		cmd = m.scheduleRefreshTick()
		return m, cmd
	case SnapshotMsg:
		m.snapshot = mergeSnapshot(m.snapshot, msg.Snapshot)
	case ProgressMsg:
		m.progress = applyProgress(m.progress, msg)
		state := strings.ToLower(strings.TrimSpace(msg.State))
		switch state {
		case "complete":
			m.appendNotification("info", fmt.Sprintf("%s complete", msg.Action))
		case "failed":
			m.appendNotification("error", fmt.Sprintf("%s failed: %s", msg.Action, strings.TrimSpace(msg.Detail)))
		}
	}
	return m, nil
}

func (m Model) updateDashboardKey(msg tea.KeyMsg) (Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?", "h":
		m.showHelp = !m.showHelp
		if m.showHelp {
			m.activeTab = tabHelp
		} else {
			m.activeTab = tabDashboard
		}
		return m, nil
	case "/":
		m.showHelp = false
		m.showPalette = true
		m.palette.Reset()
		m.palette.Focus()
		return m, nil
	case "i":
		m.showHelp = false
		m.showIdentity = true
		return m, nil
	case "tab", "right", "l":
		m.activeTab = (m.activeTab + 1) % len(m.tabs)
		m.showHelp = m.activeTab == tabHelp
		return m, nil
	case "shift+tab", "left", "H":
		m.activeTab = (m.activeTab + len(m.tabs) - 1) % len(m.tabs)
		m.showHelp = m.activeTab == tabHelp
		return m, nil
	case "1":
		m.activeTab = tabDashboard
		m.showHelp = false
		return m, nil
	case "2":
		m.activeTab = tabEndpoints
		m.showHelp = false
		return m, nil
	case "3":
		m.activeTab = tabActivity
		m.showHelp = false
		return m, nil
	case "4":
		m.activeTab = tabHelp
		m.showHelp = true
		return m, nil
	case "r":
		// Manual refresh: applies the injected RefreshSource immediately
		// without interfering with the periodic ticker. Pure local read.
		if m.refresh != nil {
			m.snapshot = mergeSnapshot(m.snapshot, m.refresh())
		}
		return m, nil
	}
	return m, nil
}

func (m Model) updatePalette(msg tea.KeyMsg) Model {
	switch msg.String() {
	case "esc":
		m.showPalette = false
		m.palette.Reset()
		m.palette.Blur()
		return m
	case "ctrl+c":
		m.showPalette = false
		m.palette.Reset()
		m.palette.Blur()
		return m
	case "enter":
		m.applyPaletteAction()
		m.showPalette = false
		m.palette.Reset()
		m.palette.Blur()
		return m
	}
	now := m.clock()
	updated, _ := m.palette.Update(msg, now)
	m.palette = updated
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
	query := strings.ToLower(strings.TrimSpace(m.palette.Value()))
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
	if overflow := len(m.snapshot.Notifications) - maxNotifications; overflow > 0 {
		copy(m.snapshot.Notifications, m.snapshot.Notifications[overflow:])
		m.snapshot.Notifications = m.snapshot.Notifications[:maxNotifications]
	}
}

// View renders the active section, modal, or help overlay.
func (m Model) View() string {
	if m.showPalette {
		return m.renderCommandPalette()
	}
	if m.showIdentity {
		return m.renderIdentitySetup()
	}
	if m.showHelp || m.activeTab == tabHelp {
		return m.renderHelp()
	}
	return m.renderDashboard()
}

func (m Model) renderDashboard() string {
	header := m.th.Title.Render(fmt.Sprintf("%s %s", m.snapshot.AppName, m.snapshot.Version))
	tabs := m.renderTabs()
	status := m.renderStatusPanel()
	endpoints := m.renderEndpointsPanel()
	contextHelp := m.th.Panel.Render(strings.Join([]string{
		"Context Help",
		"Use local fixtures and injected scans; live tunnel workflows require explicit command action.",
		"/: command palette • i: identity setup • ?: safety help • q: quit",
	}, "\n"))
	footer := m.th.Footer.Render("/: command palette • i: identity setup • ?: help • h: help • q: quit • tab: next section")
	progress := m.renderProgressPanel()
	notifications := m.renderNotifications()

	sections := []string{header, tabs}

	switch m.activeTab {
	case tabEndpoints:
		sections = append(sections, m.th.Subtitle.Render("Endpoints"), endpoints, status)
	case tabActivity:
		sections = append(sections, m.th.Subtitle.Render("Activity"), progressOrPlaceholder(progress, m.th), notifications)
		if notifications == "" {
			// remove the empty entry to keep layout tidy
			sections = sections[:len(sections)-1]
		}
	default:
		sections = append(sections, "Dashboard", status, endpoints)
		if progress != "" {
			sections = append(sections, progress)
		}
		if notifications != "" {
			sections = append(sections, notifications)
		}
	}
	if m.activeTab == tabActivity && progress == "" && notifications == "" {
		sections = append(sections, m.th.Muted.Render("No active work; trigger an action via /."))
	}
	sections = append(sections, contextHelp, footer)
	return lipgloss.JoinVertical(lipgloss.Left, sections...) + "\n"
}

func progressOrPlaceholder(rendered string, th theme) string {
	if rendered == "" {
		return th.Muted.Render("No async actions in progress.")
	}
	return rendered
}

func (m Model) renderTabs() string {
	parts := make([]string, 0, len(m.tabs)*2-1)
	for index, name := range m.tabs {
		style := m.th.TabInactive
		if index == m.activeTab {
			style = m.th.TabActive
		}
		parts = append(parts, style.Render(fmt.Sprintf("%d %s", index+1, name)))
		if index < len(m.tabs)-1 {
			parts = append(parts, m.th.TabSeparator.Render("│"))
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m Model) renderStatusPanel() string {
	warp := m.snapshot.Status.WARP
	proxy := m.snapshot.Status.Proxy
	rows := []string{
		"Status",
		fmt.Sprintf("WARP: %s", warp),
		fmt.Sprintf("Proxy: %s", proxy),
		m.snapshot.Status.Message,
	}
	if !m.focused {
		rows = append(rows, m.th.Muted.Render("(window blurred — refresh paused)"))
	}
	return m.th.Panel.Render(strings.Join(rows, "\n"))
}

func (m Model) renderEndpointsPanel() string {
	return m.th.Panel.Render("Endpoints\n" + m.endpointRows())
}

func (m Model) endpointRows() string {
	if len(m.snapshot.Endpoints) == 0 {
		return m.th.Muted.Render("No endpoints available; use static/injected scan sources.")
	}
	rows := []string{fmt.Sprintf("%-30s  %-9s  %s", "Address", "Health", "Detail")}
	for _, endpoint := range m.snapshot.Endpoints {
		label := "unhealthy"
		style := m.th.Unhealthy
		detail := endpoint.Error
		if endpoint.Healthy {
			label = "healthy"
			style = m.th.Healthy
			detail = endpoint.RTT.String()
		}
		if detail == "" {
			detail = "not probed"
		}
		// Width fixes the visible column even when ANSI escape codes
		// wrap the underlying token, so rows stay aligned across
		// healthy/unhealthy state changes.
		health := style.Width(9).Render(label)
		rows = append(rows, fmt.Sprintf("%-30s  %s  %s", endpoint.Address, health, detail))
	}
	return strings.Join(rows, "\n")
}

func (m Model) renderProgressPanel() string {
	if len(m.progress) == 0 {
		return ""
	}
	frame := spinnerFrame(m.tickSeq)
	rows := []string{"In Progress"}
	for _, entry := range m.progress {
		row := fmt.Sprintf("%s %s — %s", m.th.Spinner.Render(frame), entry.Action, entry.State)
		if entry.Detail != "" {
			row += " (" + entry.Detail + ")"
		}
		rows = append(rows, row)
	}
	return m.th.Panel.Render(strings.Join(rows, "\n"))
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
		styled := level
		switch level {
		case "WARNING":
			styled = m.th.Warning.Render(level)
		case "ERROR":
			styled = m.th.Error.Render(level)
		case "ACTION":
			styled = m.th.Action.Render(level)
		case "INFO":
			styled = m.th.Info.Render(level)
		}
		rows = append(rows, fmt.Sprintf("%s: %s", styled, message))
	}
	if len(rows) == 0 {
		return ""
	}
	return m.th.Panel.Render("Toast\n" + strings.Join(rows, "\n"))
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
	return m.th.Panel.Render(strings.Join(rows, "\n")) + "\n"
}

func identitySetupFieldLabels() []string {
	return []string{"Device ID", "Private Key", "Interface Addresses", "Peer Public Key", "Endpoint", "DNS"}
}

func (m Model) renderIdentityField(index int) string {
	value := m.identityFieldValueAt(index)
	if index == 1 {
		if value == "" {
			return m.th.Muted.Render("hidden input empty")
		}
		// Mask material with a fixed-width six-bullet preview so the
		// rendered output always contains four-or-more bullets even
		// when the underlying value is longer or shorter, satisfying
		// the masking contract without leaking length.
		return "•••••• (hidden)"
	}
	if strings.TrimSpace(value) == "" {
		return m.th.Muted.Render("empty")
	}
	return value
}

func (m Model) identityValidationPreview() string {
	_, err := warp.ImportManualIdentity(warp.ManualIdentity{
		DeviceID:           m.identitySetup.deviceID,
		PrivateKey:         m.identitySetup.privateKey,
		InterfaceAddresses: textutil.SplitCSV(m.identitySetup.interfaceAddresses),
		PeerPublicKey:      m.identitySetup.peerPublicKey,
		Endpoint:           m.identitySetup.endpoint,
		DNS:                textutil.SplitCSV(m.identitySetup.dns),
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

func trimLastRune(value string) string {
	if value == "" {
		return ""
	}
	runes := []rune(value)
	return string(runes[:len(runes)-1])
}

func (m Model) renderCommandPalette() string {
	query := strings.ToLower(strings.TrimSpace(m.palette.Value()))
	rows := []string{
		"Command Palette",
		fmt.Sprintf("query: %s", m.palette.Value()),
		"",
	}
	matched := 0
	for _, entry := range commandPaletteEntries() {
		search := strings.ToLower(entry.Name + " " + entry.Description)
		if query != "" && !strings.Contains(search, query) {
			continue
		}
		rows = append(rows, fmt.Sprintf("- %s — %s", entry.Name, entry.Description))
		matched++
	}
	if matched == 0 {
		rows = append(rows, m.th.Muted.Render("No matching local commands"))
	}
	rows = append(rows, "", "esc: close • enter: run highlighted command • type to search")
	return m.th.Panel.Render(strings.Join(rows, "\n")) + "\n"
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
		"  /         open command palette",
		"  i         open guided manual identity setup preview",
		"  tab/1..4  switch dashboard sections",
		"  r         apply injected snapshot refresh",
		"  ? / h     toggle help",
		"  q         quit",
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
	return m.th.Panel.Render(body) + "\n"
}

// mergeSnapshot keeps existing fields when the incoming snapshot
// leaves them blank, so partial refresh sources can update only the
// pieces they own without erasing the rest.
func mergeSnapshot(current, incoming Snapshot) Snapshot {
	out := current
	if strings.TrimSpace(incoming.AppName) != "" {
		out.AppName = incoming.AppName
	}
	if strings.TrimSpace(incoming.Version) != "" {
		out.Version = incoming.Version
	}
	if strings.TrimSpace(incoming.Status.WARP) != "" {
		out.Status.WARP = incoming.Status.WARP
	}
	if strings.TrimSpace(incoming.Status.Proxy) != "" {
		out.Status.Proxy = incoming.Status.Proxy
	}
	if strings.TrimSpace(incoming.Status.Message) != "" {
		out.Status.Message = incoming.Status.Message
	}
	if incoming.Endpoints != nil {
		out.Endpoints = incoming.Endpoints
	}
	if incoming.Notifications != nil {
		out.Notifications = incoming.Notifications
	}
	return out
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
