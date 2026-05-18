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
	Rotation  RotationSettings
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

type RotationSettings struct {
	Strategies           []string
	TimedIntervalSeconds int
	FailureThreshold     int
	MaxLatencyMS         int
	MaxAttempts          int
	CooldownSeconds      int
	HistoryPath          string
	TargetLabels         []string
	RegionLabels         []string
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
	AutoMTU             bool
	MTUMin              int
	MTUMax              int
	MTUStep             int
}

type ProxySettings struct {
	Enabled            bool
	ListenAddress      string
	AllowedClientCIDRs []string
	RateLimitPerMinute int
	RateLimitBurst     int
	TLSMode            string
}

type SafetySettings struct {
	AccountAutomation         bool
	AccountAutomationConsent  bool
	WARPPlusGeneration        bool
	WARPPlusGenerationConsent bool
	DPIEvasion                bool
	DPIEvasionConsent         bool
	StreamingUnlock           bool
	StreamingUnlockConsent    bool
}

// ValidationIssue describes one actionable, non-secret configuration problem.
type ValidationIssue struct {
	Path    string
	Message string
	Help    string
}

const (
	unsupportedDPIEvasionMessage = "DPI evasion is not implemented in this version"
	unsupportedDPIEvasionHelp    = "keep dpi_evasion = false until a future release implements bounded DPI behavior"
	unsupportedTLSModeMessage    = "TLS proxy mode is not implemented in this version"
	unsupportedTLSModeHelp       = "set tls_mode = \"disabled\" until inbound/outbound TLS proxy semantics are implemented"
)

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
		Rotation: RotationSettings{
			Strategies:           []string{"latency", "failure"},
			TimedIntervalSeconds: 60,
			FailureThreshold:     1,
			MaxAttempts:          3,
			CooldownSeconds:      60,
			HistoryPath:          "configs/warpshift.rotation-history.json",
			TargetLabels:         []string{"general"},
			RegionLabels:         []string{"global"},
		},
		Identity: IdentitySettings{StorePath: "configs/warpshift.identity.json"},
		WireGuard: WireGuardSettings{
			OutputPath:          "configs/warpshift.wg.conf",
			Endpoint:            "engage.cloudflareclient.com:2408",
			DNS:                 []string{"1.1.1.1", "1.0.0.1"},
			AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
			PersistentKeepalive: 25,
			MTU:                 1280,
			AutoMTU:             false,
			MTUMin:              1280,
			MTUMax:              1420,
			MTUStep:             10,
		},
		Proxy: ProxySettings{
			Enabled:            false,
			ListenAddress:      "127.0.0.1:0",
			AllowedClientCIDRs: []string{"127.0.0.0/8", "::1/128"},
			RateLimitPerMinute: 120,
			RateLimitBurst:     20,
			TLSMode:            "disabled",
		},
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
	validateRotationSettings(settings.Rotation, add)
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
	validateMTUDetectionSettings(settings.WireGuard, add)
	if err := validateListenAddress(settings.Proxy.ListenAddress); err != nil {
		add("proxy.listen_address", err.Error(), "use host:port for the local proxy bind")
	}
	validateProxyHardeningSettings(settings.Proxy, add)
	requirePrivateUseConsent := func(enabled, consent bool, flagPath, consentPath, consentKey, workflow string) {
		if enabled && !consent {
			add(consentPath, fmt.Sprintf("requires explicit private-use consent for %s", workflow), fmt.Sprintf("set %s = true only for private use you control, or disable %s", consentKey, flagPath))
		}
	}
	requirePrivateUseConsent(settings.Safety.AccountAutomation, settings.Safety.AccountAutomationConsent, "safety.account_automation", "safety.account_automation_consent", "account_automation_consent", "account automation")
	requirePrivateUseConsent(settings.Safety.WARPPlusGeneration, settings.Safety.WARPPlusGenerationConsent, "safety.warp_plus_generation", "safety.warp_plus_generation_consent", "warp_plus_generation_consent", "WARP+ workflows")
	if settings.Safety.DPIEvasion {
		add("safety.dpi_evasion", unsupportedDPIEvasionMessage, unsupportedDPIEvasionHelp)
	}
	requirePrivateUseConsent(settings.Safety.DPIEvasion, settings.Safety.DPIEvasionConsent, "safety.dpi_evasion", "safety.dpi_evasion_consent", "dpi_evasion_consent", "DPI evasion")
	requirePrivateUseConsent(settings.Safety.StreamingUnlock, settings.Safety.StreamingUnlockConsent, "safety.streaming_unlock", "safety.streaming_unlock_consent", "streaming_unlock_consent", "streaming unlock")
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

func validateRotationSettings(settings RotationSettings, add func(string, string, string)) {
	if len(settings.Strategies) == 0 {
		add("rotation.strategies", "must include at least one strategy", "use latency, failure, and/or timed")
		return
	}
	hasFailure := false
	hasTimed := false
	for _, strategy := range settings.Strategies {
		switch strings.TrimSpace(strategy) {
		case "latency":
		case "failure":
			hasFailure = true
		case "timed":
			hasTimed = true
		default:
			add("rotation.strategies", "contains an unsupported strategy", "use latency, failure, and/or timed")
			return
		}
	}
	if hasFailure && settings.FailureThreshold <= 0 {
		add("rotation.failure_threshold", "must be positive for failure-based rotation", "set failure_threshold to 1 or greater")
	}
	if hasTimed && settings.TimedIntervalSeconds <= 0 {
		add("rotation.timed_interval_seconds", "must be positive for timed rotation", "set timed_interval_seconds to 1 or greater")
	}
	if settings.MaxLatencyMS < 0 {
		add("rotation.max_latency_ms", "cannot be negative", "use 0 or a positive latency budget")
	}
	if settings.MaxAttempts <= 0 {
		add("rotation.max_attempts", "must be positive", "set max_attempts to a small positive value")
	}
	if settings.CooldownSeconds < 0 {
		add("rotation.cooldown_seconds", "cannot be negative", "use 0 or a positive cooldown")
	}
	if strings.TrimSpace(settings.HistoryPath) == "" {
		add("rotation.history_path", "is required", "provide a local path for rotation history")
	}
	for _, label := range append(append([]string{}, settings.TargetLabels...), settings.RegionLabels...) {
		if strings.TrimSpace(label) == "" {
			add("rotation.labels", "cannot contain empty labels", "remove empty target or region labels")
			return
		}
	}
}

func validateMTUDetectionSettings(settings WireGuardSettings, add func(string, string, string)) {
	if settings.MTUMin < 576 {
		add("wireguard.mtu_min", "must be at least 576", "use a conservative lower bound such as 1280")
	}
	if settings.MTUMax < settings.MTUMin {
		add("wireguard.mtu_range", "max must be greater than or equal to min", "set mtu_max at or above mtu_min")
	}
	if settings.MTUStep <= 0 {
		add("wireguard.mtu_step", "must be positive", "use a bounded positive step such as 10")
	}
}

func validateProxyHardeningSettings(settings ProxySettings, add func(string, string, string)) {
	if len(settings.AllowedClientCIDRs) == 0 {
		add("proxy.allowed_client_cidrs", "must include at least one CIDR", "keep localhost CIDRs unless explicitly exposing a private proxy")
	}
	for _, cidr := range settings.AllowedClientCIDRs {
		if strings.TrimSpace(cidr) == "" {
			add("proxy.allowed_client_cidrs", "cannot contain empty values", "remove empty CIDR entries")
			break
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			add("proxy.allowed_client_cidrs", "must contain CIDR ranges", "use values such as 127.0.0.0/8 or ::1/128")
			break
		}
	}
	if settings.RateLimitPerMinute < 0 {
		add("proxy.rate_limit_per_minute", "cannot be negative", "use 0 for defaults or a positive per-minute limit")
	}
	if settings.RateLimitBurst < 0 {
		add("proxy.rate_limit_burst", "cannot be negative", "use 0 for defaults or a positive burst")
	}
	if !strings.EqualFold(strings.TrimSpace(settings.TLSMode), "disabled") {
		add("proxy.tls_mode", unsupportedTLSModeMessage, unsupportedTLSModeHelp)
	}
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
	case "rotation.strategies":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.Rotation.Strategies = values
	case "rotation.timed_interval_seconds":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("timed_interval_seconds must be an integer")
		}
		settings.Rotation.TimedIntervalSeconds = value
	case "rotation.failure_threshold":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("failure_threshold must be an integer")
		}
		settings.Rotation.FailureThreshold = value
	case "rotation.max_latency_ms":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("max_latency_ms must be an integer")
		}
		settings.Rotation.MaxLatencyMS = value
	case "rotation.max_attempts":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("max_attempts must be an integer")
		}
		settings.Rotation.MaxAttempts = value
	case "rotation.cooldown_seconds":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("cooldown_seconds must be an integer")
		}
		settings.Rotation.CooldownSeconds = value
	case "rotation.history_path":
		settings.Rotation.HistoryPath = parseString(raw)
	case "rotation.target_labels":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.Rotation.TargetLabels = values
	case "rotation.region_labels":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.Rotation.RegionLabels = values
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
	case "wireguard.auto_mtu":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("auto_mtu must be a boolean")
		}
		settings.WireGuard.AutoMTU = value
	case "wireguard.mtu_min":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("mtu_min must be an integer")
		}
		settings.WireGuard.MTUMin = value
	case "wireguard.mtu_max":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("mtu_max must be an integer")
		}
		settings.WireGuard.MTUMax = value
	case "wireguard.mtu_step":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("mtu_step must be an integer")
		}
		settings.WireGuard.MTUStep = value
	case "proxy.enabled":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("enabled must be a boolean")
		}
		settings.Proxy.Enabled = value
	case "proxy.listen_address":
		settings.Proxy.ListenAddress = parseString(raw)
	case "proxy.allowed_client_cidrs":
		values, err := parseStringArray(raw)
		if err != nil {
			return err
		}
		settings.Proxy.AllowedClientCIDRs = values
	case "proxy.rate_limit_per_minute":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("rate_limit_per_minute must be an integer")
		}
		settings.Proxy.RateLimitPerMinute = value
	case "proxy.rate_limit_burst":
		value, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("rate_limit_burst must be an integer")
		}
		settings.Proxy.RateLimitBurst = value
	case "proxy.tls_mode":
		settings.Proxy.TLSMode = parseString(raw)
	case "safety.account_automation":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("account_automation must be a boolean")
		}
		settings.Safety.AccountAutomation = value
	case "safety.account_automation_consent":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("account_automation_consent must be a boolean")
		}
		settings.Safety.AccountAutomationConsent = value
	case "safety.warp_plus_generation":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("warp_plus_generation must be a boolean")
		}
		settings.Safety.WARPPlusGeneration = value
	case "safety.warp_plus_generation_consent":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("warp_plus_generation_consent must be a boolean")
		}
		settings.Safety.WARPPlusGenerationConsent = value
	case "safety.dpi_evasion":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("dpi_evasion must be a boolean")
		}
		settings.Safety.DPIEvasion = value
	case "safety.dpi_evasion_consent":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("dpi_evasion_consent must be a boolean")
		}
		settings.Safety.DPIEvasionConsent = value
	case "safety.streaming_unlock":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("streaming_unlock must be a boolean")
		}
		settings.Safety.StreamingUnlock = value
	case "safety.streaming_unlock_consent":
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("streaming_unlock_consent must be a boolean")
		}
		settings.Safety.StreamingUnlockConsent = value
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
