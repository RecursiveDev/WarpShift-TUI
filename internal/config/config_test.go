package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[app]
startup_mode = "tui"

[warp]
status_source = "local"

[identity]
store_path = "state/identity.json"

[wireguard]
output_path = "exports/warp.conf"
endpoint = "engage.cloudflareclient.com:2408"
dns = ["1.1.1.1", "1.0.0.1"]
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25
mtu = 1280

[proxy]
enabled = false
listen_address = "127.0.0.1:0"

[safety]
account_automation = false
warp_plus_generation = false
dpi_evasion = false
streaming_unlock = false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}

	if settings.App.StartupMode != "tui" {
		t.Fatalf("startup mode = %q, want tui", settings.App.StartupMode)
	}
	if settings.Warp.StatusSource != "local" {
		t.Fatalf("warp status source = %q, want local", settings.Warp.StatusSource)
	}
	if settings.Identity.StorePath != "state/identity.json" {
		t.Fatalf("identity store path = %q", settings.Identity.StorePath)
	}
	if settings.WireGuard.OutputPath != "exports/warp.conf" {
		t.Fatalf("wireguard output path = %q", settings.WireGuard.OutputPath)
	}
	if settings.WireGuard.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Fatalf("wireguard endpoint = %q", settings.WireGuard.Endpoint)
	}
	if got := strings.Join(settings.WireGuard.AllowedIPs, ","); got != "0.0.0.0/0,::/0" {
		t.Fatalf("allowed IPs = %q", got)
	}
	if settings.WireGuard.PersistentKeepalive != 25 {
		t.Fatalf("persistent keepalive = %d", settings.WireGuard.PersistentKeepalive)
	}
	if settings.WireGuard.MTU != 1280 {
		t.Fatalf("mtu = %d", settings.WireGuard.MTU)
	}
}

func TestLoadEndpointStaticSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[endpoint]
static = ["162.159.192.10:2408", "162.159.193.20:2408"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if got := strings.Join(settings.Endpoint.Static, ","); got != "162.159.192.10:2408,162.159.193.20:2408" {
		t.Fatalf("endpoint static sources = %q", got)
	}
}

func TestLoadAllowsPrivateUseSafetyFlagsWithExplicitConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[safety]
account_automation = true
account_automation_consent = true
warp_plus_generation = true
warp_plus_generation_consent = true
dpi_evasion = true
dpi_evasion_consent = true
streaming_unlock = true
streaming_unlock_consent = true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if !settings.Safety.AccountAutomation || !settings.Safety.AccountAutomationConsent {
		t.Fatalf("account automation consent gate was not loaded: %+v", settings.Safety)
	}
	if !settings.Safety.WARPPlusGeneration || !settings.Safety.WARPPlusGenerationConsent {
		t.Fatalf("WARP+ consent gate was not loaded: %+v", settings.Safety)
	}
	if !settings.Safety.DPIEvasion || !settings.Safety.DPIEvasionConsent {
		t.Fatalf("DPI evasion consent gate was not loaded: %+v", settings.Safety)
	}
	if !settings.Safety.StreamingUnlock || !settings.Safety.StreamingUnlockConsent {
		t.Fatalf("streaming unlock consent gate was not loaded: %+v", settings.Safety)
	}
}

func TestLoadRequiresConsentForPrivateUseSafetyFlags(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[safety]
account_automation = true
warp_plus_generation = false
dpi_evasion = false
streaming_unlock = false
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected missing private-use consent to be rejected")
	}
	for _, want := range []string{
		"safety.account_automation_consent",
		"requires explicit private-use consent",
		"account_automation_consent = true",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("validation error missing %q in %q", want, err.Error())
		}
	}
	for _, forbidden := range []string{"private_key", "access_token", "secret"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatalf("validation error leaked credential wording %q in %q", forbidden, err.Error())
		}
	}
}

func TestValidateReportsMultipleActionableIssues(t *testing.T) {
	settings := DefaultSettings()
	settings.App.StartupMode = "daemon"
	settings.Warp.StatusSource = "remote"
	settings.Identity.StorePath = ""
	settings.Safety.DPIEvasion = true

	err := Validate(settings)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	message := err.Error()
	for _, want := range []string{
		"configuration validation failed",
		"app.startup_mode",
		"set to tui or cli",
		"warp.status_source",
		"set to local",
		"identity.store_path",
		"provide a local path",
		"safety.dpi_evasion_consent",
		"requires explicit private-use consent",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("validation error missing %q in %q", want, message)
		}
	}
	for _, forbidden := range []string{"private_key", "access_token", "secret"} {
		if strings.Contains(strings.ToLower(message), forbidden) {
			t.Fatalf("validation error leaked credential wording %q in %q", forbidden, message)
		}
	}
}

func TestExampleConfigLoadsWithoutCredentialMaterial(t *testing.T) {
	path := filepath.Join("..", "..", "configs", "warpshift.example.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read example config: %v", err)
	}

	lower := strings.ToLower(string(data))
	for _, forbidden := range []string{"private_key", "privatekey", "license_key", "access_token", "secret"} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("example config contains forbidden credential marker %q", forbidden)
		}
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load example config returned unexpected error: %v", err)
	}
	if settings.Identity.StorePath == "" {
		t.Fatal("example config should resolve a local identity store path")
	}
	if settings.WireGuard.OutputPath == "" {
		t.Fatal("example config should resolve a WireGuard output path")
	}
}

func TestLoadRotationPolicySettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[rotation]
strategies = ["latency", "failure", "timed"]
timed_interval_seconds = 120
failure_threshold = 2
max_latency_ms = 150
max_attempts = 3
cooldown_seconds = 90
history_path = "state/rotation-history.json"
target_labels = ["general"]
region_labels = ["global"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write rotation config fixture: %v", err)
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if got := strings.Join(settings.Rotation.Strategies, ","); got != "latency,failure,timed" {
		t.Fatalf("rotation strategies = %q", got)
	}
	if settings.Rotation.TimedIntervalSeconds != 120 || settings.Rotation.FailureThreshold != 2 || settings.Rotation.MaxLatencyMS != 150 {
		t.Fatalf("rotation timing/failure settings = %+v", settings.Rotation)
	}
	if settings.Rotation.MaxAttempts != 3 || settings.Rotation.CooldownSeconds != 90 || settings.Rotation.HistoryPath != "state/rotation-history.json" {
		t.Fatalf("rotation execution settings = %+v", settings.Rotation)
	}
	if strings.Join(settings.Rotation.TargetLabels, ",") != "general" || strings.Join(settings.Rotation.RegionLabels, ",") != "global" {
		t.Fatalf("rotation labels = targets=%v regions=%v", settings.Rotation.TargetLabels, settings.Rotation.RegionLabels)
	}
}

func TestLoadPhase6HardeningSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[wireguard]
auto_mtu = true
mtu_min = 1280
mtu_max = 1420
mtu_step = 20

[proxy]
enabled = true
listen_address = "127.0.0.1:0"
allowed_client_cidrs = ["127.0.0.0/8", "::1/128"]
rate_limit_per_minute = 60
rate_limit_burst = 10
tls_mode = "disabled"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write hardening config fixture: %v", err)
	}

	settings, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned unexpected error: %v", err)
	}
	if !settings.WireGuard.AutoMTU || settings.WireGuard.MTUMin != 1280 || settings.WireGuard.MTUMax != 1420 || settings.WireGuard.MTUStep != 20 {
		t.Fatalf("wireguard MTU hardening settings = %+v", settings.WireGuard)
	}
	if strings.Join(settings.Proxy.AllowedClientCIDRs, ",") != "127.0.0.0/8,::1/128" {
		t.Fatalf("proxy allowlist = %v", settings.Proxy.AllowedClientCIDRs)
	}
	if settings.Proxy.RateLimitPerMinute != 60 || settings.Proxy.RateLimitBurst != 10 || settings.Proxy.TLSMode != "disabled" {
		t.Fatalf("proxy hardening settings = %+v", settings.Proxy)
	}
}

func TestValidateRejectsUnsafePhase6Settings(t *testing.T) {
	settings := DefaultSettings()
	settings.Proxy.AllowedClientCIDRs = []string{"not-a-cidr"}
	settings.Proxy.RateLimitPerMinute = -1
	settings.WireGuard.AutoMTU = true
	settings.WireGuard.MTUMin = 500
	settings.WireGuard.MTUMax = 400
	settings.WireGuard.MTUStep = 0

	err := Validate(settings)
	if err == nil {
		t.Fatal("expected invalid hardening settings to be rejected")
	}
	message := err.Error()
	for _, want := range []string{"proxy.allowed_client_cidrs", "proxy.rate_limit_per_minute", "wireguard.mtu_min", "wireguard.mtu_range", "wireguard.mtu_step"} {
		if !strings.Contains(message, want) {
			t.Fatalf("validation error missing %q in %q", want, message)
		}
	}
}
