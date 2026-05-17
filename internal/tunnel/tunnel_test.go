package tunnel

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"
)

const (
	testPrivateKey = "MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI="
	testPeerKey    = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY="
)

func TestBuildConfigConvertsIdentityAndSelectedEndpointToUAPI(t *testing.T) {
	identity := testIdentity(t)
	endpoint := testEndpoint(t)

	cfg, err := BuildConfig(*identity, endpoint, Config{MTU: 1420, PersistentKeepalive: 30})
	if err != nil {
		t.Fatalf("BuildConfig returned unexpected error: %v", err)
	}

	if cfg.Endpoint != "162.159.192.10:2408" {
		t.Fatalf("Endpoint = %q, want selected endpoint", cfg.Endpoint)
	}
	if cfg.MTU != 1420 {
		t.Fatalf("MTU = %d, want 1420", cfg.MTU)
	}
	if len(cfg.InterfaceAddresses) != 1 || cfg.InterfaceAddresses[0].String() != "172.16.0.2" {
		t.Fatalf("InterfaceAddresses = %#v, want 172.16.0.2", cfg.InterfaceAddresses)
	}
	for _, want := range []string{
		"private" + "_key=3132333435363738393031323334353637383930313233343536373839303132",
		"public" + "_key=6162636465666768696a6b6c6d6e6f707172737475767778797a313233343536",
		"replace_allowed_ips=true",
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"endpoint=162.159.192.10:2408",
		"persistent_keepalive_interval=30",
	} {
		if !strings.Contains(cfg.UAPI, want) {
			t.Fatalf("UAPI missing %q in:\n%s", want, cfg.UAPI)
		}
	}
}

func TestBuildConfigRejectsInvalidKeyWithoutLeakingSecret(t *testing.T) {
	secret := "not-base64-secret"
	identity := warp.Identity{
		PrivateKey:         secret,
		PeerPublicKey:      testPeerKey,
		InterfaceAddresses: []string{"172.16.0.2/32"},
		Endpoint:           "engage.cloudflareclient.com:2408",
		DNS:                []string{"1.1.1.1"},
	}

	_, err := BuildConfig(identity, testEndpoint(t), Config{})
	if err == nil {
		t.Fatal("expected invalid key to be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked private key material: %v", err)
	}
}

func TestNewDialerUsesBackendFactoryAndDialContext(t *testing.T) {
	identity := testIdentity(t)
	endpoint := testEndpoint(t)
	backend := &fakeBackend{}
	var got RuntimeConfig

	dialer, err := NewDialer(context.Background(), *identity, endpoint, Config{}, withBackendFactory(func(ctx context.Context, cfg RuntimeConfig) (backendDialer, error) {
		if ctx == nil {
			t.Fatal("context passed to backend factory was nil")
		}
		got = cfg
		return backend, nil
	}))
	if err != nil {
		t.Fatalf("NewDialer returned unexpected error: %v", err)
	}
	defer dialer.Close()

	conn, err := dialer.DialContext(context.Background(), "tcp", "example.test:443")
	if err != nil {
		t.Fatalf("DialContext returned unexpected error: %v", err)
	}
	conn.Close()

	if got.Endpoint != "162.159.192.10:2408" {
		t.Fatalf("backend Endpoint = %q, want selected endpoint", got.Endpoint)
	}
	if backend.network != "tcp" || backend.address != "example.test:443" || backend.calls != 1 {
		t.Fatalf("backend dial = %s %s calls=%d, want tcp example.test:443 calls=1", backend.network, backend.address, backend.calls)
	}
	dialer.Close()
	if !backend.closed {
		t.Fatal("Close did not close backend")
	}
}

func TestNewDialerSanitizesBackendErrors(t *testing.T) {
	identity := testIdentity(t)
	secretErr := errors.New("backend saw " + testPrivateKey)

	_, err := NewDialer(context.Background(), *identity, testEndpoint(t), Config{}, withBackendFactory(func(context.Context, RuntimeConfig) (backendDialer, error) {
		return nil, secretErr
	}))
	if err == nil {
		t.Fatal("expected backend error")
	}
	if strings.Contains(err.Error(), testPrivateKey) {
		t.Fatalf("error leaked private key material: %v", err)
	}
}

type fakeBackend struct {
	calls   int
	network string
	address string
	closed  bool
}

func (b *fakeBackend) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	b.calls++
	b.network = network
	b.address = address
	left, right := net.Pipe()
	right.Close()
	return left, nil
}

func (b *fakeBackend) Close() error {
	b.closed = true
	return nil
}

func testIdentity(t *testing.T) *warp.Identity {
	t.Helper()
	identity, err := warp.ImportManualIdentity(warp.ManualIdentity{
		DeviceID:           "manual-device",
		PrivateKey:         testPrivateKey,
		InterfaceAddresses: []string{"172.16.0.2/32"},
		PeerPublicKey:      testPeerKey,
		Endpoint:           "engage.cloudflareclient.com:2408",
		DNS:                []string{"1.1.1.1"},
	})
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}
	return identity
}

func testEndpoint(t *testing.T) warp.Endpoint {
	t.Helper()
	endpoint, err := warp.NewEndpoint("162.159.192.10", 2408, warp.TransportUDP)
	if err != nil {
		t.Fatalf("NewEndpoint returned unexpected error: %v", err)
	}
	return endpoint
}
