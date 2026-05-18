package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RecursiveDev/WarpShift-TUI/internal/app"
	"github.com/RecursiveDev/WarpShift-TUI/internal/proxy"
	"github.com/RecursiveDev/WarpShift-TUI/internal/tui"
	"github.com/RecursiveDev/WarpShift-TUI/internal/tunnel"
	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"
)

func newTestCommand(t *testing.T, options ...Option) (*Command, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	application, err := app.New(app.Metadata{Name: "WarpShift-TUI", Version: "dev"})
	if err != nil {
		t.Fatalf("app.New returned unexpected error: %v", err)
	}

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return New(application, stdout, stderr, options...), stdout, stderr
}

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

func newConcurrentTestCommand(t *testing.T, options ...Option) (*Command, *lockedBuffer, *lockedBuffer) {
	t.Helper()
	application, err := app.New(app.Metadata{Name: "WarpShift-TUI", Version: "dev"})
	if err != nil {
		t.Fatalf("app.New returned unexpected error: %v", err)
	}

	stdout := &lockedBuffer{}
	stderr := &lockedBuffer{}
	return New(application, stdout, stderr, options...), stdout, stderr
}

func TestRunVersion(t *testing.T) {
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"--version"})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if got, want := stdout.String(), "WarpShift-TUI dev\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRunHelpDocumentsCommandsAndSafeScope(t *testing.T) {
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"--help"})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	help := stdout.String()
	for _, want := range []string{
		"Usage: warpshift <command>",
		"tui",
		"config validate",
		"identity import",
		"identity inspect",
		"profile import",
		"profile list",
		"profile show",
		"profile switch",
		"profile delete",
		"wireguard export",
		"wireguard mtu",
		"trace parse",
		"endpoint scan",
		"endpoint pool",
		"rotation inspect",
		"rotation plan",
		"rotation run",
		"rotation report",
		"proxy start",
		"account register",
		"account status",
		"account devices",
		"account rename",
		"account deactivate",
		"account delete",
		"license bind",
		"license status",
		"manual identity import remains available as a consent-free local path",
		"profile storage uses named local identities",
		"endpoint pool expansion is deterministic and local-first",
		"rotation plan/report are local-first; rotation run requires safety.streaming_unlock_consent and an injected target probe",
		"account automation requires safety.account_automation_consent",
		"WARP+ license binding requires safety.warp_plus_generation_consent for user-owned keys",
		"DPI-related workflows remain unimplemented",
		"localhost proxy defaults",
		"authentication required for remote proxy binds",
		"proxy allowlisting and rate limiting",
		"WireGuard MTU helper uses injected probes",
		"users are responsible for enabled private-use workflows",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("help output missing %q in %q", want, help)
		}
	}
}

func TestRunRejectsUnknownFlags(t *testing.T) {
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"--warp-plus"})

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "unknown flag") {
		t.Fatalf("stderr = %q, want unknown flag message", stderr.String())
	}
}

func TestTUILaunchUsesInjectedLauncher(t *testing.T) {
	called := false
	command, stdout, stderr := newTestCommand(t, WithTUILauncher(func(ctx context.Context, snapshot tui.Snapshot) error {
		called = true
		if snapshot.AppName != "WarpShift-TUI" || snapshot.Version != "dev" {
			t.Fatalf("snapshot metadata = %#v", snapshot)
		}
		if len(snapshot.Endpoints) == 0 {
			t.Fatal("snapshot should include static endpoint rows")
		}
		return nil
	}))

	exitCode := command.Run(context.Background(), []string{"tui"})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !called {
		t.Fatal("TUI launcher was not called")
	}
	if !strings.Contains(stdout.String(), "TUI exited") {
		t.Fatalf("stdout = %q, want TUI exit message", stdout.String())
	}
}

func TestConfigValidateLoadsSafeConfig(t *testing.T) {
	path := writeSafeConfig(t)
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"config", "validate", "--config", path})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "configuration valid") {
		t.Fatalf("stdout = %q, want validation message", stdout.String())
	}
}

func TestConfigValidateReportsActionableIssues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[app]
startup_mode = "daemon"
[safety]
account_automation = false
warp_plus_generation = false
dpi_evasion = false
streaming_unlock = true
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"config", "validate", "--config", path})

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	for _, want := range []string{
		"configuration validation failed",
		"- app.startup_mode:",
		"set to tui or cli",
		"- safety.streaming_unlock_consent:",
		"requires explicit private-use consent",
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr missing %q in %q", want, stderr.String())
		}
	}
}

func TestIdentityImportAndInspectDoNotPrintSecrets(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "manual.json")
	store := filepath.Join(dir, "store", "identity.json")
	secret := "super-secret-private-key"
	writeManualIdentity(t, input, secret)
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"identity", "import", "--input", input, "--store", store})
	if exitCode != 0 {
		t.Fatalf("import exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("identity import printed private key material")
	}
	if !strings.Contains(stdout.String(), "manual identity imported") {
		t.Fatalf("stdout = %q, want import confirmation", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"identity", "inspect", "--store", store})
	if exitCode != 0 {
		t.Fatalf("inspect exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, secret) || strings.Contains(output, "peer-public-key") {
		t.Fatal("identity inspect printed key material")
	}
	for _, want := range []string{"identity present", "interface_addresses=1", "dns=1", "endpoint=engage.cloudflareclient.com:2408"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("inspect output missing %q in %q", want, stdout.String())
		}
	}
}

func TestIdentityInspectSurfacesPermissionGuidanceWithoutSecrets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are platform-specific; permission guidance is validated on Unix")
	}
	dir := t.TempDir()
	store := filepath.Join(dir, "identity.json")
	secret := "permission-secret-private-key"
	writeManualIdentity(t, store, secret)
	if err := os.Chmod(store, 0o644); err != nil {
		t.Fatalf("chmod identity fixture: %v", err)
	}
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"identity", "inspect", "--store", store})

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	message := stdout.String() + stderr.String()
	for _, want := range []string{"identity file permissions", "chmod 600", store} {
		if !strings.Contains(message, want) {
			t.Fatalf("permission guidance missing %q in %q", want, message)
		}
	}
	if strings.Contains(message, secret) {
		t.Fatal("permission guidance leaked private key material")
	}
}

func TestWireGuardExportDoesNotPrintProfileSecrets(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "manual.json")
	store := filepath.Join(dir, "identity.json")
	output := filepath.Join(dir, "warp.conf")
	secret := "private-for-profile"
	writeManualIdentity(t, input, secret)
	if _, err := warp.ImportManualIdentityFile(input, store); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"wireguard", "export", "--identity", store, "--output", output})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("wireguard export printed private key material")
	}
	profile, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read exported profile: %v", err)
	}
	if !strings.Contains(string(profile), "PrivateKey = "+secret) {
		t.Fatalf("exported profile missing private key material")
	}
}

func TestTraceParseReportsStatusWithoutNetwork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trace.txt")
	if err := os.WriteFile(path, []byte("ip=203.0.113.10\nwarp=on\n"), 0o600); err != nil {
		t.Fatalf("write trace: %v", err)
	}
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"trace", "parse", "--file", path})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	for _, want := range []string{"warp=on", "healthy=true"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("trace output missing %q in %q", want, stdout.String())
		}
	}
}

func TestAccountRegisterStatusDeleteAndLicenseCLIUseFakeAPIWithConsent(t *testing.T) {
	dir := t.TempDir()
	configPath := writePrivateUseConfig(t, dir, true, true)
	storePath := filepath.Join(dir, "identity.json")
	licenseKey := "license-secret-value"
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/reg":
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode registration request: %v", err)
			}
			if strings.TrimSpace(body["key"]) == "" {
				t.Fatal("registration request missing public key")
			}
			writeCLIAPIStatus(t, w, "limited")
		case r.Method == http.MethodGet && r.URL.Path == "/reg/device-secret-id":
			if r.Header.Get("Authorization") != "Bearer token-secret-value" {
				t.Fatal("Authorization header did not contain expected bearer token")
			}
			writeCLIAPIStatus(t, w, "limited")
		case r.Method == http.MethodPatch && r.URL.Path == "/reg/device-secret-id/account":
			if r.Header.Get("Authorization") != "Bearer token-secret-value" {
				t.Fatal("Authorization header did not contain expected bearer token")
			}
			var body map[string]string
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("decode license request: %v", err)
			}
			if body["license"] != licenseKey {
				t.Fatal("license request body did not contain submitted key")
			}
			writeCLIAPIStatus(t, w, "premium")
		case r.Method == http.MethodDelete && r.URL.Path == "/reg/device-secret-id":
			if r.Header.Get("Authorization") != "Bearer token-secret-value" {
				t.Fatal("Authorization header did not contain expected bearer token")
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected API request: method=%s pathRecognized=%t", r.Method, isExpectedPhase2APIPath(r.URL.Path))
		}
	}))
	defer server.Close()

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"account", "register", "--config", configPath, "--store", storePath, "--api-base-url", server.URL})
	if exitCode != 0 {
		t.Fatalf("account register exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	registrationOutput := stdout.String() + stderr.String()
	if strings.Contains(registrationOutput, "device-secret-id") || strings.Contains(registrationOutput, "token-secret-value") {
		t.Fatal("registration output leaked sensitive material")
	}
	if !strings.Contains(stdout.String(), "WARP account registered") {
		t.Fatalf("registration output missing confirmation: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"account", "status", "--config", configPath, "--identity", storePath, "--api-base-url", server.URL})
	if exitCode != 0 {
		t.Fatalf("account status exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	statusOutput := stdout.String() + stderr.String()
	if strings.Contains(statusOutput, "device-secret-id") {
		t.Fatal("status output leaked identity material")
	}
	for _, want := range []string{"account_type=limited", "device_name=test-phone", "device_type=Android", "bound_devices=2"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("status output missing %q: stdout=%q stderr=%q", want, stdout.String(), stderr.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"account", "devices", "--config", configPath, "--identity", storePath, "--api-base-url", server.URL})
	if exitCode != 0 {
		t.Fatalf("account devices exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	devicesOutput := stdout.String() + stderr.String()
	if strings.Contains(devicesOutput, "device-secret-id") || strings.Contains(devicesOutput, "device-secondary-id") {
		t.Fatal("devices output leaked device identifiers")
	}
	for _, want := range []string{"bound devices: count=2", "name=test-phone", "current=true", "name=laptop", "current=false"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("devices output missing %q in %q", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"license", "bind", "--config", configPath, "--identity", storePath, "--license-key", licenseKey, "--api-base-url", server.URL})
	if exitCode != 0 {
		t.Fatalf("license bind exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	licenseOutput := stdout.String() + stderr.String()
	if strings.Contains(licenseOutput, licenseKey) {
		t.Fatal("license output leaked key material")
	}
	if !strings.Contains(stdout.String(), "WARP+ license bound") {
		t.Fatalf("license output missing confirmation: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"account", "delete", "--config", configPath, "--identity", storePath, "--api-base-url", server.URL, "--remove-local"})
	if exitCode != 0 {
		t.Fatalf("account delete exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "WARP device deregistered") || !strings.Contains(stdout.String(), "local identity removed") {
		t.Fatalf("delete output missing cleanup confirmation: %q", stdout.String())
	}
	if _, err := os.Stat(storePath); !os.IsNotExist(err) {
		t.Fatalf("identity store still exists after --remove-local: err=%v", err)
	}
	expectedRequests := []struct {
		label string
		value string
	}{
		{label: "registration", value: "POST /reg"},
		{label: "status lookup", value: "GET /reg/device-secret-id"},
		{label: "license bind", value: "PATCH /reg/device-secret-id/account"},
		{label: "delete", value: "DELETE /reg/device-secret-id"},
	}
	for _, expected := range expectedRequests {
		if !containsString(requests, expected.value) {
			t.Fatalf("API request sequence missing %s request; requestCount=%d", expected.label, len(requests))
		}
	}
}

func TestAccountAndLicenseCLIRequireConsentBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	configPath := writePrivateUseConfig(t, dir, false, false)
	storePath := filepath.Join(dir, "identity.json")
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"account", "register", "--config", configPath, "--store", storePath, "--api-base-url", server.URL})
	if exitCode != 2 {
		t.Fatalf("account register exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "account_automation_consent") {
		t.Fatalf("expected consent guidance without stdout; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	writeManualIdentity(t, storePath, base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))
	exitCode = command.Run(context.Background(), []string{"license", "bind", "--config", configPath, "--identity", storePath, "--license-key", "license-secret-value", "--api-base-url", server.URL})
	if exitCode != 2 {
		t.Fatalf("license bind exit code = %d, want 2", exitCode)
	}
	if strings.Contains(stderr.String(), "license-secret-value") {
		t.Fatal("license consent guidance leaked license key")
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "warp_plus_generation_consent") {
		t.Fatalf("expected redacted license consent guidance; stdoutLen=%d hasConsentGuidance=%t", stdout.Len(), strings.Contains(stderr.String(), "warp_plus_generation_consent"))
	}
	if called {
		t.Fatal("CLI contacted API before consent")
	}
}

func TestAccountAndLicenseCLIRejectUnsafeRemoteAPIBaseURL(t *testing.T) {
	dir := t.TempDir()
	configPath := writePrivateUseConfig(t, dir, true, true)
	storePath := filepath.Join(dir, "identity.json")
	licenseKey := "license-secret-value"

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"account", "register", "--config", configPath, "--store", storePath, "--api-base-url", "https://example.com/v0a2158"})
	if exitCode != 2 {
		t.Fatalf("account register exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "localhost/loopback test servers") {
		t.Fatalf("expected loopback-only API base URL guidance; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	writeManualIdentityWithToken(t, storePath, base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))
	exitCode = command.Run(context.Background(), []string{"license", "bind", "--config", configPath, "--identity", storePath, "--license-key", licenseKey, "--api-base-url", "https://example.com/v0a2158"})
	if exitCode != 2 {
		t.Fatalf("license bind exit code = %d, want 2", exitCode)
	}
	output := stdout.String() + stderr.String()
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "localhost/loopback test servers") {
		t.Fatalf("expected loopback-only license guidance; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	for _, secret := range []string{licenseKey, "token-secret-value", "device-secret-id"} {
		if strings.Contains(output, secret) {
			t.Fatalf("remote API base URL rejection leaked secret %q in output=%q", secret, output)
		}
	}
}

func TestLicenseCLIRejectsGenerationSubcommandsWithoutNetwork(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"license", "generate", "--api-base-url", server.URL, "--license-key", "license-secret-value"})
	if exitCode != 2 {
		t.Fatalf("license generate exit code = %d, want 2", exitCode)
	}
	output := stdout.String() + stderr.String()
	if !strings.Contains(stderr.String(), "unknown subcommand") || strings.Contains(output, "license-secret-value") {
		t.Fatalf("expected unknown-subcommand rejection without secret echo; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("unsupported WARP+ generation command contacted API")
	}
}

func TestAccountRenameAndDeactivateExposeUnsupportedWithoutNetwork(t *testing.T) {
	dir := t.TempDir()
	configPath := writePrivateUseConfig(t, dir, true, false)
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"account", "rename", "--config", configPath, "--name", "new-name"})
	if exitCode != 2 {
		t.Fatalf("account rename exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "not implemented") {
		t.Fatalf("rename output = stdout=%q stderr=%q, want unsupported guidance", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"account", "deactivate", "--config", configPath})
	if exitCode != 2 {
		t.Fatalf("account deactivate exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "not implemented") || !strings.Contains(stderr.String(), "account delete") {
		t.Fatalf("deactivate output = stdout=%q stderr=%q, want unsupported delete guidance", stdout.String(), stderr.String())
	}
	if called {
		t.Fatal("unsupported account management commands contacted API")
	}
}

func TestEndpointScanUsesInjectedProbeAndStaticSources(t *testing.T) {
	command, stdout, stderr := newTestCommand(t, WithEndpointProbe(func(ctx context.Context, endpoint warp.Endpoint) (time.Duration, error) {
		switch endpoint.Address {
		case "162.159.193.20":
			return 15 * time.Millisecond, nil
		case "162.159.192.10":
			return 40 * time.Millisecond, nil
		default:
			return 0, fmt.Errorf("unexpected endpoint")
		}
	}))

	exitCode := command.Run(context.Background(), []string{"endpoint", "scan", "--static", "162.159.192.10:2408,162.159.193.20:2408"})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	output := stdout.String()
	first := strings.Index(output, "162.159.193.20:2408/udp")
	second := strings.Index(output, "162.159.192.10:2408/udp")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("scan output not ranked by injected RTT: %q", output)
	}
	if !strings.Contains(output, "15ms") || !strings.Contains(output, "40ms") {
		t.Fatalf("scan output missing RTTs: %q", output)
	}
}

func TestEndpointScanUsesConfigStaticSourcesWhenFlagOmitted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warpshift.toml")
	content := `
[endpoint]
static = ["162.159.194.30:2408", "162.159.195.40:2408"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config fixture: %v", err)
	}
	seen := map[string]bool{}
	command, stdout, stderr := newTestCommand(t, WithEndpointProbe(func(ctx context.Context, endpoint warp.Endpoint) (time.Duration, error) {
		seen[endpoint.Address] = true
		if endpoint.Address == "162.159.195.40" {
			return 10 * time.Millisecond, nil
		}
		return 30 * time.Millisecond, nil
	}))

	exitCode := command.Run(context.Background(), []string{"endpoint", "scan", "--config", path})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !seen["162.159.194.30"] || !seen["162.159.195.40"] || len(seen) != 2 {
		t.Fatalf("probe saw endpoints %#v, want config static sources only", seen)
	}
	output := stdout.String()
	first := strings.Index(output, "162.159.195.40:2408/udp")
	second := strings.Index(output, "162.159.194.30:2408/udp")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("scan output not ranked from config sources: %q", output)
	}
}

func TestProxyValidateAndStartPreserveAuthBoundaries(t *testing.T) {
	command, _, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"proxy", "validate", "--listen", "0.0.0.0:1080"})
	if exitCode != 2 {
		t.Fatalf("remote validate exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "authentication is required") {
		t.Fatalf("stderr = %q, want authentication guidance", stderr.String())
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command, startStdout, startStderr := newConcurrentTestCommand(t)
	done := make(chan int, 1)
	go func() {
		done <- command.Run(ctx, []string{"proxy", "start", "--listen", "127.0.0.1:0"})
	}()

	addr := waitForProxyAddress(t, startStdout, "SOCKS5")
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("SOCKS5 listener address = %q, want localhost ephemeral port", addr)
	}
	cancel()
	if exitCode = waitForExitCode(t, done); exitCode != 0 {
		t.Fatalf("start exit code = %d, want 0; stderr=%q", exitCode, startStderr.String())
	}
	for _, want := range []string{"SOCKS5 proxy listening", "auth=false", "proxy stopped"} {
		if !strings.Contains(startStdout.String(), want) {
			t.Fatalf("proxy start output missing %q in %q", want, startStdout.String())
		}
	}
}

func TestProxyValidateDocumentsHardeningFlags(t *testing.T) {
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"proxy", "validate", "--listen", "127.0.0.1:0", "--allow-cidr", "127.0.0.0/8,::1/128", "--rate-limit-per-minute", "30", "--rate-limit-burst", "5"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	for _, want := range []string{"proxy configuration valid", "allowlist=127.0.0.0/8,::1/128", "rate_limit=30/min burst=5"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("proxy validate output missing %q in %q", want, stdout.String())
		}
	}
}

func TestProxyValidateHonorsConfiguredEnabledFlag(t *testing.T) {
	dir := t.TempDir()
	disabledPath := filepath.Join(dir, "proxy-disabled.toml")
	if err := os.WriteFile(disabledPath, []byte(`
[proxy]
enabled = false
listen_address = "127.0.0.1:0"
tls_mode = "disabled"
`), 0o600); err != nil {
		t.Fatalf("write disabled proxy config: %v", err)
	}

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"proxy", "validate", "--config", disabledPath})
	if exitCode != 0 {
		t.Fatalf("disabled proxy validate exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "proxy disabled by config") {
		t.Fatalf("stdout = %q, want disabled proxy message", stdout.String())
	}

	enabledPath := filepath.Join(dir, "proxy-enabled.toml")
	if err := os.WriteFile(enabledPath, []byte(`
[proxy]
enabled = true
listen_address = "127.0.0.1:0"
allowed_client_cidrs = ["127.0.0.0/8"]
rate_limit_per_minute = 42
rate_limit_burst = 7
tls_mode = "disabled"
`), 0o600); err != nil {
		t.Fatalf("write enabled proxy config: %v", err)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"proxy", "validate", "--config", enabledPath})
	if exitCode != 0 {
		t.Fatalf("enabled proxy validate exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	for _, want := range []string{"proxy configuration valid", "allowlist=127.0.0.0/8", "rate_limit=42/min burst=7"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("enabled proxy output missing %q in %q", want, stdout.String())
		}
	}
}

func TestWireGuardMTUUsesInjectedProbe(t *testing.T) {
	probed := []int{}
	command, stdout, stderr := newTestCommand(t, WithMTUProbe(func(_ context.Context, candidate int) (bool, error) {
		probed = append(probed, candidate)
		return candidate <= 1300, nil
	}))

	exitCode := command.Run(context.Background(), []string{"wireguard", "mtu", "--min", "1280", "--max", "1320", "--step", "20"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Join(strings.Fields(fmt.Sprint(probed)), ",") != "[1320,1300]" {
		t.Fatalf("probed candidates = %v, want [1320 1300]", probed)
	}
	for _, want := range []string{"mtu recommendation", "mtu=1300", "probed=true"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("wireguard mtu output missing %q in %q", want, stdout.String())
		}
	}
}

func TestProxyStartWithIdentityBuildsWarpTunnelDialer(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "identity.json")
	secret := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	writeManualIdentity(t, store, secret)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	built := false
	command, stdout, stderr := newConcurrentTestCommand(t, WithProxyDialerBuilder(func(ctx context.Context, identity warp.Identity, endpoint warp.Endpoint, cfg tunnel.Config) (proxy.Dialer, error) {
		built = true
		if identity.DeviceID != "manual-device" {
			t.Fatalf("identity DeviceID = %q, want manual-device", identity.DeviceID)
		}
		if endpoint.Address != "162.159.192.10" || endpoint.Port != 2408 {
			t.Fatalf("endpoint = %#v, want selected WARP endpoint", endpoint)
		}
		if cfg.MTU == 0 || cfg.PersistentKeepalive == 0 {
			t.Fatalf("tunnel config missing defaults: %#v", cfg)
		}
		return fakeProxyDialer{}, nil
	}))

	done := make(chan int, 1)
	go func() {
		done <- command.Run(ctx, []string{"proxy", "start", "--listen", "127.0.0.1:0", "--identity", store, "--endpoint", "162.159.192.10:2408"})
	}()

	_ = waitForProxyAddress(t, stdout, "SOCKS5")
	cancel()
	exitCode := waitForExitCode(t, done)
	if exitCode != 0 {
		t.Fatalf("start exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !built {
		t.Fatal("proxy start did not build WARP tunnel dialer")
	}
	output := stdout.String() + stderr.String()
	if strings.Contains(output, secret) {
		t.Fatal("proxy start printed private key material")
	}
	for _, want := range []string{"SOCKS5 proxy listening", "warp tunnel dialer ready", "auth=false", "proxy stopped"} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("proxy start output missing %q in %q", want, stdout.String())
		}
	}
}

func TestProxyStartServesSOCKS5WithInjectedTunnelDialerAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "identity.json")
	writeManualIdentity(t, store, base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))

	requested := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command, stdout, stderr := newConcurrentTestCommand(t, WithProxyDialerBuilder(func(ctx context.Context, identity warp.Identity, endpoint warp.Endpoint, cfg tunnel.Config) (proxy.Dialer, error) {
		return proxyDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			requested <- address
			clientSide, targetSide := net.Pipe()
			go func() {
				defer targetSide.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(targetSide, buf); err == nil {
					_, _ = targetSide.Write(buf)
				}
			}()
			return clientSide, nil
		}), nil
	}))

	done := make(chan int, 1)
	go func() {
		done <- command.Run(ctx, []string{"proxy", "start", "--listen", "127.0.0.1:0", "--identity", store, "--endpoint", "162.159.192.10:2408"})
	}()

	addr := waitForProxyAddress(t, stdout, "SOCKS5")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial SOCKS5 listener: %v; stderr=%q", err, stderr.String())
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	mustWrite(t, conn, []byte{0x05, 0x01, 0x00})
	mustRead(t, conn, []byte{0x05, 0x00})

	host := []byte("example.com")
	request := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	request = append(request, 0x00, 0x50)
	mustWrite(t, conn, request)
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS5 connect reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("SOCKS5 connect reply = %#v, want success", reply)
	}
	mustWrite(t, conn, []byte("ping"))
	mustRead(t, conn, []byte("ping"))

	select {
	case got := <-requested:
		if got != "example.com:80" {
			t.Fatalf("dialed address = %q, want example.com:80", got)
		}
	case <-time.After(time.Second):
		t.Fatal("SOCKS5 listener did not use injected dialer")
	}
	cancel()
	if exitCode := waitForExitCode(t, done); exitCode != 0 {
		t.Fatalf("start exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
}

func TestProxyStartServesHTTPOnlyWithInjectedTunnelDialerAndGracefulShutdown(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "identity.json")
	writeManualIdentity(t, store, base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012")))

	requested := make(chan string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command, stdout, stderr := newConcurrentTestCommand(t, WithProxyDialerBuilder(func(ctx context.Context, identity warp.Identity, endpoint warp.Endpoint, cfg tunnel.Config) (proxy.Dialer, error) {
		return proxyDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			requested <- address
			clientSide, targetSide := net.Pipe()
			go func() {
				defer targetSide.Close()
				buffer := make([]byte, 1)
				var request strings.Builder
				for !strings.Contains(request.String(), "\r\n\r\n") {
					if _, err := targetSide.Read(buffer); err != nil {
						return
					}
					request.WriteByte(buffer[0])
				}
				_, _ = targetSide.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
			}()
			return clientSide, nil
		}), nil
	}))

	done := make(chan int, 1)
	go func() {
		done <- command.Run(ctx, []string{"proxy", "start", "--http-listen", "127.0.0.1:0", "--identity", store, "--endpoint", "162.159.192.10:2408"})
	}()

	addr := waitForProxyAddress(t, stdout, "HTTP")
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial HTTP listener: %v; stderr=%q", err, stderr.String())
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	mustWrite(t, conn, []byte("GET http://example.com/resource HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	response := make([]byte, 128)
	n, err := conn.Read(response)
	if err != nil {
		t.Fatalf("read HTTP proxy response: %v", err)
	}
	if got := string(response[:n]); !strings.Contains(got, "200 OK") || !strings.Contains(got, "ok") {
		t.Fatalf("HTTP proxy response = %q, want proxied OK response", got)
	}

	select {
	case got := <-requested:
		if got != "example.com:80" {
			t.Fatalf("dialed address = %q, want example.com:80", got)
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP listener did not use injected dialer")
	}
	cancel()
	if exitCode := waitForExitCode(t, done); exitCode != 0 {
		t.Fatalf("start exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
}

func TestProfileCLIWorkflowsDoNotPrintSecrets(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "manual.json")
	storeDir := filepath.Join(dir, "profiles")
	secret := "profile-cli-secret-private-key"
	writeManualIdentity(t, input, secret)
	command, stdout, stderr := newTestCommand(t)

	exitCode := command.Run(context.Background(), []string{"profile", "import", "--name", "alpha", "--input", input, "--store-dir", storeDir})
	if exitCode != 0 {
		t.Fatalf("profile import exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if strings.Contains(stdout.String()+stderr.String(), secret) {
		t.Fatal("profile import printed private key material")
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"profile", "switch", "--name", "alpha", "--store-dir", storeDir})
	if exitCode != 0 {
		t.Fatalf("profile switch exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"profile", "list", "--store-dir", storeDir})
	if exitCode != 0 {
		t.Fatalf("profile list exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "* alpha") {
		t.Fatalf("profile list output missing active profile marker: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"profile", "show", "--name", "alpha", "--store-dir", storeDir})
	if exitCode != 0 {
		t.Fatalf("profile show exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	showOutput := stdout.String() + stderr.String()
	if strings.Contains(showOutput, secret) || strings.Contains(showOutput, "peer-public-key") {
		t.Fatal("profile show printed key material")
	}
	if !strings.Contains(stdout.String(), "profile alpha") || !strings.Contains(stdout.String(), "endpoint=engage.cloudflareclient.com:2408") {
		t.Fatalf("profile show output missing safe metadata: %q", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"profile", "delete", "--name", "../escape", "--store-dir", storeDir})
	if exitCode != 2 {
		t.Fatalf("profile delete traversal exit code = %d, want 2", exitCode)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"profile", "delete", "--name", "alpha", "--store-dir", storeDir})
	if exitCode != 0 {
		t.Fatalf("profile delete exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "profile alpha deleted") {
		t.Fatalf("profile delete output missing confirmation: %q", stdout.String())
	}
}

func TestEndpointPoolAndRotationCLIUseConsentAwarePlanningData(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "warpshift.toml")
	content := `
[rotation]
strategies = ["latency", "failure", "timed"]
timed_interval_seconds = 120
failure_threshold = 2
max_latency_ms = 150
target_labels = ["general"]
region_labels = ["global"]
`
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write rotation config: %v", err)
	}

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"endpoint", "pool", "--max-per-prefix", "1", "--ipv6", "--port", "2408"})
	if exitCode != 0 {
		t.Fatalf("endpoint pool exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	poolOutput := stdout.String()
	if !strings.Contains(poolOutput, "162.159.192.1:2408/udp") || !strings.Contains(poolOutput, "[2606:4700:d0::1]:2408/udp") {
		t.Fatalf("endpoint pool output missing deterministic IPv4/IPv6 endpoints: %q", poolOutput)
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"rotation", "inspect", "--config", configPath})
	if exitCode != 0 {
		t.Fatalf("rotation inspect exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	rotationOutput := stdout.String() + stderr.String()
	for _, want := range []string{"strategies=latency,failure,timed", "failure_threshold=2", "timed_interval=120s", "target_labels=general", "region_labels=global"} {
		if !strings.Contains(rotationOutput, want) {
			t.Fatalf("rotation output missing %q in %q", want, rotationOutput)
		}
	}
	if strings.Contains(strings.ToLower(rotationOutput), "streaming unlock probing") {
		t.Fatalf("rotation inspect output implied direct streaming probing: %q", rotationOutput)
	}
}

func TestRotationPlanRunReportConsentGatedAndLocalProbes(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "rotation-history.json")
	withoutConsent := writeStreamingRotationConfig(t, dir, false, historyPath)
	withConsent := writeStreamingRotationConfig(t, dir, true, historyPath)

	probeCalls := 0
	command, stdout, stderr := newTestCommand(t, WithTargetProbe(func(ctx context.Context, candidate warp.StreamingRotationCandidate, targetLabels []string) warp.StreamingTargetProbeResult {
		probeCalls++
		return warp.StreamingTargetProbeResult{OK: true, Latency: 25 * time.Millisecond}
	}))

	exitCode := command.Run(context.Background(), []string{"rotation", "plan", "--config", withoutConsent, "--max-candidates", "2", "--target-label", "general"})
	if exitCode != 0 {
		t.Fatalf("rotation plan exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if probeCalls != 0 {
		t.Fatalf("rotation plan invoked target probe %d times, want 0", probeCalls)
	}
	for _, want := range []string{"rotation plan", "candidate", "162.159."} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("rotation plan output missing %q in %q", want, stdout.String())
		}
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"rotation", "run", "--config", withoutConsent, "--history", historyPath})
	if exitCode != 2 {
		t.Fatalf("rotation run without consent exit code = %d, want 2", exitCode)
	}
	if probeCalls != 0 {
		t.Fatalf("rotation run without consent invoked target probe %d times, want 0", probeCalls)
	}
	if !strings.Contains(stderr.String(), "safety.streaming_unlock") {
		t.Fatalf("rotation run without consent stderr = %q, want consent guidance", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"rotation", "run", "--config", withConsent, "--history", historyPath, "--max-attempts", "1", "--target-label", "general"})
	if exitCode != 0 {
		t.Fatalf("rotation run exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if probeCalls != 1 {
		t.Fatalf("rotation run probe calls = %d, want 1", probeCalls)
	}
	if !strings.Contains(stdout.String(), "rotation run selected") || strings.Contains(strings.ToLower(stdout.String()+stderr.String()), "private_key") {
		t.Fatalf("rotation run output = %q stderr=%q, want safe selection message", stdout.String(), stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	exitCode = command.Run(context.Background(), []string{"rotation", "report", "--history", historyPath})
	if exitCode != 0 {
		t.Fatalf("rotation report exit code = %d, want 0; stderr=%q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "rotation history") || !strings.Contains(stdout.String(), "target_ok=true") {
		t.Fatalf("rotation report output = %q, want stored safe history", stdout.String())
	}
	for _, forbidden := range []string{"private_key", "peer_public_key", "license", "token"} {
		if strings.Contains(strings.ToLower(stdout.String()+stderr.String()), forbidden) {
			t.Fatalf("rotation CLI leaked forbidden marker %q in output=%q stderr=%q", forbidden, stdout.String(), stderr.String())
		}
	}
}

func TestRotationRunDefaultTargetProbeFailsClosed(t *testing.T) {
	dir := t.TempDir()
	historyPath := filepath.Join(dir, "rotation-history-default.json")
	configPath := writeStreamingRotationConfig(t, dir, true, historyPath)

	command, stdout, stderr := newTestCommand(t)
	exitCode := command.Run(context.Background(), []string{"rotation", "run", "--config", configPath, "--history", historyPath, "--max-attempts", "1", "--target-label", "general"})
	if exitCode != 2 {
		t.Fatalf("rotation run default probe exit code = %d, want 2", exitCode)
	}
	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "streaming target probe is not configured") {
		t.Fatalf("expected fail-closed target probe guidance; stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(historyPath); !os.IsNotExist(err) {
		t.Fatalf("default target probe should fail closed before writing history; stat err=%v", err)
	}
}

type fakeProxyDialer struct{}

func (fakeProxyDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	left, right := net.Pipe()
	right.Close()
	return left, nil
}

type proxyDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f proxyDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func waitForProxyAddress(t *testing.T, output *lockedBuffer, label string) string {
	t.Helper()
	prefix := label + " proxy listening on "
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(output.String(), "\n") {
			if strings.HasPrefix(line, prefix) {
				fields := strings.Fields(strings.TrimPrefix(line, prefix))
				if len(fields) > 0 {
					return fields[0]
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s listener; output=%q", label, output.String())
	return ""
}

func waitForExitCode(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case exitCode := <-done:
		return exitCode
	case <-time.After(2 * time.Second):
		t.Fatal("proxy start did not stop after context cancellation")
		return -1
	}
}

func mustWrite(t *testing.T, conn net.Conn, payload []byte) {
	t.Helper()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
}

func mustRead(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read payload: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("read payload = %#v, want %#v", got, want)
	}
}

func writePrivateUseConfig(t *testing.T, dir string, accountConsent, warpPlusConsent bool) string {
	t.Helper()
	path := filepath.Join(dir, "warpshift.toml")
	content := fmt.Sprintf(`
[app]
startup_mode = "cli"
[warp]
status_source = "local"
[identity]
store_path = %q
[wireguard]
output_path = %q
endpoint = "engage.cloudflareclient.com:2408"
dns = ["1.1.1.1"]
allowed_ips = ["0.0.0.0/0", "::/0"]
persistent_keepalive = 25
mtu = 1280
[proxy]
enabled = false
listen_address = "127.0.0.1:0"
[safety]
account_automation = %t
account_automation_consent = %t
warp_plus_generation = %t
warp_plus_generation_consent = %t
dpi_evasion = false
streaming_unlock = false
`, filepath.Join(dir, "identity.json"), filepath.Join(dir, "warp.conf"), accountConsent, accountConsent, warpPlusConsent, warpPlusConsent)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write private-use config: %v", err)
	}
	return path
}

func writeCLIAPIStatus(t *testing.T, w http.ResponseWriter, accountType string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	clientID := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := fmt.Fprintf(w, `{"id":"device-secret-id","name":"test-phone","type":"Android","active":true,"token":"token-secret-value","account":{"id":"account-secret-id","account_type":%q,"devices":[{"id":"device-secret-id","name":"test-phone","type":"Android","active":true},{"id":"device-secondary-id","name":"laptop","type":"Windows","active":false}]},"config":{"client_id":%q,"interface":{"addresses":{"v4":"172.16.0.2","v6":"2606:4700:110:abcd::2"}},"peers":[{"public_key":"peer-public-key","endpoint":{"host":"engage.cloudflareclient.com:2408"}}]}}`, accountType, clientID); err != nil {
		t.Fatalf("write API status: %v", err)
	}
}

func isExpectedPhase2APIPath(path string) bool {
	switch path {
	case "/reg", "/reg/device-secret-id", "/reg/device-secret-id/account":
		return true
	default:
		return false
	}
}

func writeStreamingRotationConfig(t *testing.T, dir string, consent bool, historyPath string) string {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("streaming-%t.toml", consent))
	content := fmt.Sprintf(`
[app]
startup_mode = "cli"
[rotation]
strategies = ["latency", "failure"]
failure_threshold = 1
max_attempts = 2
cooldown_seconds = 60
history_path = %q
target_labels = ["general"]
region_labels = ["global"]
[safety]
streaming_unlock = %t
streaming_unlock_consent = %t
`, historyPath, consent, consent)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write streaming rotation config: %v", err)
	}
	return path
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func writeSafeConfig(t *testing.T) string {
	t.Helper()
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
dns = ["1.1.1.1"]
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
		t.Fatalf("write config: %v", err)
	}
	return path
}

func writeManualIdentity(t *testing.T, path, privateKey string) {
	t.Helper()
	content := fmt.Sprintf(`{
  "device_id": "manual-device",
  "private_key": %q,
  "interface_addresses": ["172.16.0.2/32"],
  "peer_public_key": "peer-public-key",
  "endpoint": "engage.cloudflareclient.com:2408",
  "dns": ["1.1.1.1"]
}
`, privateKey)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write identity: %v", err)
	}
}

func writeManualIdentityWithToken(t *testing.T, path, privateKey string) {
	t.Helper()
	content := fmt.Sprintf(`{
  "device_id": "device-secret-id",
  "token": "token-secret-value",
  "private_key": %q,
  "interface_addresses": ["172.16.0.2/32"],
  "peer_public_key": "peer-public-key",
  "endpoint": "engage.cloudflareclient.com:2408",
  "dns": ["1.1.1.1"]
}
`, privateKey)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write identity with token: %v", err)
	}
}
