package config

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// Settings contains local, non-secret application configuration.
type Settings struct {
	App       AppSettings
	Warp      WarpSettings
	Endpoint  EndpointSettings
	Identity  IdentitySettings
	WireGuard WireGuardSettings
	Proxy     ProxySettings
	Safety    SafetySettings
}

type AppSettings struct {
	StartupMode string
}

type WarpSettings struct {
	StatusSource string
}

type EndpointSettings struct {
	Static []string
}

type IdentitySettings struct {
	StorePath string
}

type WireGuardSettings struct {
	OutputPath          string
	Endpoint            string
	DNS                 []string
	AllowedIPs          []string
	PersistentKeepalive int
	MTU                 int
}

type ProxySettings struct {
	Enabled       bool
	ListenAddress string
}

type SafetySettings struct {
	AccountAutomation  bool
	WARPPlusGeneration bool
	DPIEvasion         bool
	StreamingUnlock    bool
}

// ValidationIssue describes one actionable, non-secret configuration problem.
type ValidationIssue struct {
	Path    string
	Message string
	Help    string
}

// ValidationError groups validation issues so CLI/TUI callers can render richer UX.
type ValidationError struct {
	Issues []ValidationIssue
}

func (e ValidationError) Error() string {
	if len(e.Issues) == 0 {
		return "configuration validation failed"
	}
	var builder strings.Builder
	builder.WriteString("configuration validation failed:")
	for _, issue := range e.Issues {
		fmt.Fprintf(&builder, "\n- %s: %s", issue.Path, issue.Message)
		if strings.TrimSpace(issue.Help) != "" {
			fmt.Fprintf(&builder, " (fix: %s)", issue.Help)
		}
	}
	return builder.String()
}

// DefaultSettings returns conservative local defaults without credential material.
func DefaultSettings() Settings {
	return Settings{
		App:  AppSettings{StartupMode: "tui"},
		Warp: WarpSettings{StatusSource: "local"},
		Endpoint: EndpointSettings{Static: []string{
			"162.159.192.10:2408",
			"162.159.193.20:2408",
		}},
		Identity: IdentitySettings{StorePath: "configs/warpshift.identity.json"},
		WireGuard: WireGuardSettings{
			OutputPath:          "configs/warpshift.wg.conf",
			Endpoint:            "engage.cloudflareclient.com:2408",
			DNS:                 []string{"1.1.1.1", "1.0.0.1"},
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
			MTU:                 1280,
		},
		Proxy:  ProxySettings{Enabled: false, ListenAddress: "127.0.0.1:0"},
		Safety: SafetySettings{},
	}
}

// Load reads and validates a local TOML configuration file.
func Load(path string) (Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Settings{}, fmt.Errorf("load config: %w", err)
	}

	settings := DefaultSettings()
	if err := parseTOML(data, &settings); err != nil {
		return Settings{}, err
	}
	if err := Validate(settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

// Validate rejects unsafe or malformed local settings.
func Validate(settings Settings) error {
	issues := ValidateIssues(settings)
	if len(issues) > 0 {
		return ValidationError{Issues: issues}
	}
	return nil
}

// ValidateIssues returns all non-secret validation issues for UI-friendly rendering.
func ValidateIssues(settings Settings) []ValidationIssue {
	var issues []ValidationIssue
	add := func(path, message, help string) {
		issues = append(issues, ValidationIssue{Path: path, Message: message, Help: help})
	}

	switch settings.App.StartupMode {
	case "tui", "cli":
	default:
		add("app.startup_mode", "must be tui or cli", "set to tui or cli")
	}
	if settings.Warp.StatusSource != "local" {
		add("warp.status_source", "must be local", "set to local")
	}
	if len(settings.Endpoint.Static) == 0 {
		add("endpoint.static", "must include at least one endpoint", "provide one or more known WARP host:port values")
	}
	for _, endpoint := range settings.Endpoint.Static {
		if err := validateEndpoint(endpoint); err != nil {
			add("endpoint.static", err.Error(), "use host:port with a non-zero port")
			break
		}
	}
	if strings.TrimSpace(settings.Identity.StorePath) == "" {
		add("identity.store_path", "is required", "provide a local path for imported identity metadata")
	}
	if strings.TrimSpace(settings.WireGuard.OutputPath) == "" {
		add("wireguard.output_path", "is required", "provide a local output path")
	}
	if err := validateEndpoint(settings.WireGuard.Endpoint); err != nil {
		add("wireguard.endpoint", err.Error(), "use host:port with a non-zero port")
	}
	for _, dns := range settings.WireGuard.DNS {
		if _, err := netip.ParseAddr(dns); err != nil {
			add("wireguard.dns", "must contain IP addresses", "use literal IPv4 or IPv6 addresses")
			break
		}
	}
	for _, allowed := range settings.WireGuard.AllowedIPs {
		if _, err := netip.ParsePrefix(allowed); err != nil {
			add("wireguard.allowed_ips", "must contain CIDR prefixes", "use CIDR notation such as 0.0.0.0/0")
			break
		}
	}
	if settings.WireGuard.PersistentKeepalive < 0 {
		add("wireguard.persistent_keepalive", "cannot be negative", "use 0 or a positive interval")
	}
	if settings.WireGuard.MTU != 0 && settings.WireGuard.MTU < 576 {
		add("wireguard.mtu", "must be at least 576 when set", "use 0 or a value of 576 or greater")
	}
	if err := validateListenAddress(settings.Proxy.ListenAddress); err != nil {
		add("proxy.listen_address", err.Error(), "use host:port for the local proxy bind")
	}
	if settings.Safety.AccountAutomation {
		add("safety.account_automation", "must remain disabled", "set to false")
	}
	if settings.Safety.WARPPlusGeneration {
		add("safety.warp_plus_generation", "must remain disabled", "set to false")
	}
	if settings.Safety.DPIEvasion {
		add("safety.dpi_evasion", "must remain disabled", "set to false")
	}
	if settings.Safety.StreamingUnlock {
		add("safety.streaming_unlock", "must remain disabled", "set to false")
	}
	return issues
}

func parseTOML(data []byte, settings *Settings) error {
	section := ""
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := stripComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		key, raw, ok := strings.Cut(line, "=")
		if !ok {
			return fmt.Errorf("config line %d: expected key = value", lineNumber)
		}
		key = strings.TrimSpace(key)
		raw = strings.TrimSpace(raw)
		if err := applySetting(settings, section, key, raw); err != nil {
			return fmt.Errorf("config line %d: %w", lineNumber, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	return nil
}

func applySetting(settings *Settings, section, key, raw string) error {
	switch section + "." + key {
	case "app.startup_mode":
		settings.App.StartupMode = parseString(raw)
	case "warp.status_source":
		settings.Warp.StatusSource = parseString(raw)
	case "endpoint.static":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.Endpoint.Static = values
	case "identity.store_path":
		settings.Identity.StorePath = parseString(raw)
	case "wireguard.output_path":
		settings.WireGuard.OutputPath = parseString(raw)
	case "wireguard.endpoint":
		settings.WireGuard.Endpoint = parseString(raw)
	case "wireguard.dns":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.WireGuard.DNS = values
	case "wireguard.allowed_ips":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.WireGuard.AllowedIPs = values
	case "wireguard.persistent_keepalive":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("persistent_keepalive must be an integer")
		}
		settings.WireGuard.PersistentKeepalive = value
	case "wireguard.mtu":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("mtu must be an integer")
		}
		settings.WireGuard.MTU = value
	case "proxy.enabled":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("enabled must be a boolean")
		}
		settings.Proxy.Enabled = value
	case "proxy.listen_address":
		settings.Proxy.ListenAddress = parseString(raw)
	case "safety.account_automation":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("account_automation must be a boolean")
		}
		settings.Safety.AccountAutomation = value
	case "safety.warp_plus_generation":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("warp_plus_generation must be a boolean")
		}
		settings.Safety.WARPPlusGeneration = value
	case "safety.dpi_evasion":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("dpi_evasion must be a boolean")
		}
		settings.Safety.DPIEvasion = value
	case "safety.streaming_unlock":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("streaming_unlock must be a boolean")
		}
		settings.Safety.StreamingUnlock = value
	default:
		return fmt.Errorf("unknown setting %s.%s", section, key)
	}
	return nil
}

func stripComment(line string) string {
	inQuote := false
	for i, r := range line {
		switch r {
		case '"':
			inQuote = !inQuote
		case '#':
			if !inQuote {
				return line[:i]
			}
		}
	}
	return line
}

func parseString(raw string) string {
	return strings.Trim(strings.TrimSpace(raw), "\"")
}

func parseStringArray(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "[") || !strings.HasSuffix(raw, "]") {
		return nil, fmt.Errorf("expected string array")
	}
	inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(raw, "["), "]"))
	if inner == "" {
		return nil, nil
	}
	parts := strings.Split(inner, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		value := parseString(part)
		if value == "" {
			return nil, fmt.Errorf("string array values cannot be empty")
		}
		values = append(values, value)
	}
	return values, nil
}

func validateEndpoint(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return fmt.Errorf("is required")
	}
	_, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return fmt.Errorf("must be host:port")
	}
	if port == "" || port == "0" {
		return fmt.Errorf("must include a non-zero port")
	}
	return nil
}

func validateListenAddress(address string) error {
	if strings.TrimSpace(address) == "" {
		return fmt.Errorf("is required")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be host:port")
	}
	if port == "" {
		return fmt.Errorf("must include a port")
	}
	return nil
}
