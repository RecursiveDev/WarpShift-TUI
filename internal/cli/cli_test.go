package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
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
		"wireguard export",
		"trace parse",
		"endpoint scan",
		"proxy validate",
		"proxy start",
		"manual identity import only",
		"localhost proxy defaults",
		"authentication required for remote proxy binds",
		"no account registration",
		"no WARP+ generation",
		"no DPI evasion",
		"no streaming unlock",
		"no Docker workflows",
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
		"- safety.streaming_unlock:",
		"must remain disabled",
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
		t.Fatalf("identity import printed secret material: stdout=%q stderr=%q", stdout.String(), stderr.String())
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
		t.Fatalf("identity inspect printed key material: %q", output)
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
		t.Fatalf("permission guidance leaked private key material: %q", message)
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
		t.Fatalf("wireguard export printed private key: stdout=%q stderr=%q", stdout.String(), stderr.String())
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
		t.Fatalf("proxy start printed private key material: %q", output)
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
