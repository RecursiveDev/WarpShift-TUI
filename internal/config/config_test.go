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

func TestLoadRejectsUnsafeSafetyFlags(t *testing.T) {
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
		t.Fatal("expected unsafe safety flag to be rejected")
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "key") {
		t.Fatalf("validation error should not mention credential material: %v", err)
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
		"safety.dpi_evasion",
		"must remain disabled",
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
