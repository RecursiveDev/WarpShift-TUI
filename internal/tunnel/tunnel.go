package tunnel

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/RecursiveDev/WarpShift-TUI/internal/proxy"
	"github.com/RecursiveDev/WarpShift-TUI/internal/warp"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const wireGuardKeyLen = 32

var defaultAllowedIPs = []string{"0.0.0.0/0", "::/0"}

// Config contains non-secret tunnel settings used to configure the userspace WireGuard backend.
type Config struct {
	AllowedIPs          []string
	DNS                 []string
	MTU                 int
	PersistentKeepalive int
}

// RuntimeConfig is the fully rendered userspace WireGuard runtime configuration.
type RuntimeConfig struct {
	InterfaceAddresses []netip.Addr
	DNSServers         []netip.Addr
	Endpoint           string
	MTU                int
	UAPI               string
}

// Dialer routes outbound proxy connections through a userspace WireGuard netstack backend.
type Dialer struct {
	backend backendDialer
	once    sync.Once
}

type backendDialer interface {
	proxy.Dialer
	Close() error
}

type backendFactory func(context.Context, RuntimeConfig) (backendDialer, error)

type options struct {
	backendFactory backendFactory
}

type Option func(*options)

func withBackendFactory(factory backendFactory) Option {
	return func(opts *options) {
		if factory != nil {
			opts.backendFactory = factory
		}
	}
}

// BuildConfig validates identity material and renders the WireGuard UAPI configuration without starting network activity.
func BuildConfig(identity warp.Identity, endpoint warp.Endpoint, cfg Config) (RuntimeConfig, error) {
	if endpoint.Transport != warp.TransportUDP {
		return RuntimeConfig{}, errors.New("warp tunnel endpoint must use udp transport")
	}
	if !warp.IsKnownCloudflareWARPEndpoint(endpoint) {
		return RuntimeConfig{}, errors.New("warp tunnel endpoint is outside known Cloudflare WARP ranges")
	}

	cfg = fillDefaults(identity, cfg)
	privateKey, err := decodeWireGuardKey(identity.PrivateKey, "private")
	if err != nil {
		return RuntimeConfig{}, err
	}
	peerKey, err := decodeWireGuardKey(identity.PeerPublicKey, "peer public")
	if err != nil {
		return RuntimeConfig{}, err
	}

	interfaceAddresses, err := parseInterfaceAddresses(identity.InterfaceAddresses)
	if err != nil {
		return RuntimeConfig{}, err
	}
	dnsServers, err := parseDNSServers(cfg.DNS)
	if err != nil {
		return RuntimeConfig{}, err
	}
	allowedIPs, err := parseAllowedIPs(cfg.AllowedIPs)
	if err != nil {
		return RuntimeConfig{}, err
	}
	if cfg.MTU < 0 || (cfg.MTU > 0 && cfg.MTU < 576) {
		return RuntimeConfig{}, errors.New("wireguard MTU must be at least 576 when set")
	}
	if cfg.PersistentKeepalive < 0 {
		return RuntimeConfig{}, errors.New("wireguard persistent keepalive cannot be negative")
	}

	endpointAddress := net.JoinHostPort(endpoint.Address, strconv.Itoa(endpoint.Port))
	return RuntimeConfig{
		InterfaceAddresses: interfaceAddresses,
		DNSServers:         dnsServers,
		Endpoint:           endpointAddress,
		MTU:                cfg.MTU,
		UAPI:               buildUAPI(privateKey, peerKey, allowedIPs, endpointAddress, cfg.PersistentKeepalive),
	}, nil
}

// NewDialer starts a userspace WireGuard backend and returns a proxy-compatible dialer.
func NewDialer(ctx context.Context, identity warp.Identity, endpoint warp.Endpoint, cfg Config, opts ...Option) (*Dialer, error) {
	if ctx == nil {
		return nil, errors.New("context is required")
	}
	runtimeConfig, err := BuildConfig(identity, endpoint, cfg)
	if err != nil {
		return nil, err
	}

	settings := options{backendFactory: newWireGuardNetstackBackend}
	for _, opt := range opts {
		if opt != nil {
			opt(&settings)
		}
	}
	backend, err := settings.backendFactory(ctx, runtimeConfig)
	if err != nil {
		return nil, sanitizeBackendError(err, identity, runtimeConfig)
	}
	return &Dialer{backend: backend}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d == nil || d.backend == nil {
		return nil, errors.New("warp tunnel dialer is not initialized")
	}
	return d.backend.DialContext(ctx, network, address)
}

func (d *Dialer) Close() error {
	if d == nil || d.backend == nil {
		return nil
	}
	var err error
	d.once.Do(func() { err = d.backend.Close() })
	return err
}

func fillDefaults(identity warp.Identity, cfg Config) Config {
	if len(cfg.AllowedIPs) == 0 {
		cfg.AllowedIPs = append([]string(nil), defaultAllowedIPs...)
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = append([]string(nil), identity.DNS...)
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.PersistentKeepalive == 0 {
		cfg.PersistentKeepalive = 25
	}
	return cfg
}

func decodeWireGuardKey(value, label string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != wireGuardKeyLen {
		return "", fmt.Errorf("wireguard %s key must be base64-encoded 32-byte material", label)
	}
	return hex.EncodeToString(decoded), nil
}

func parseInterfaceAddresses(values []string) ([]netip.Addr, error) {
	if len(values) == 0 {
		return nil, errors.New("identity interface addresses are required")
	}
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, errors.New("identity interface addresses must be CIDR prefixes")
		}
		addresses = append(addresses, prefix.Addr())
	}
	return addresses, nil
}

func parseDNSServers(values []string) ([]netip.Addr, error) {
	servers := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		server, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return nil, errors.New("wireguard DNS entries must be IP addresses")
		}
		servers = append(servers, server)
	}
	return servers, nil
}

func parseAllowedIPs(values []string) ([]string, error) {
	allowed := make([]string, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, errors.New("wireguard allowed IPs must be CIDR prefixes")
		}
		allowed = append(allowed, prefix.String())
	}
	return allowed, nil
}

func buildUAPI(privateKey, peerKey string, allowedIPs []string, endpoint string, keepalive int) string {
	var builder strings.Builder
	builder.WriteString("private_key=")
	builder.WriteString(privateKey)
	builder.WriteByte('\n')
	builder.WriteString("public_key=")
	builder.WriteString(peerKey)
	builder.WriteByte('\n')
	builder.WriteString("replace_allowed_ips=true\n")
	for _, allowed := range allowedIPs {
		builder.WriteString("allowed_ip=")
		builder.WriteString(allowed)
		builder.WriteByte('\n')
	}
	builder.WriteString("endpoint=")
	builder.WriteString(endpoint)
	builder.WriteByte('\n')
	if keepalive > 0 {
		builder.WriteString("persistent_keepalive_interval=")
		builder.WriteString(strconv.Itoa(keepalive))
		builder.WriteByte('\n')
	}
	return builder.String()
}

func sanitizeBackendError(err error, identity warp.Identity, cfg RuntimeConfig) error {
	if err == nil {
		return nil
	}
	message := err.Error()
	redactions := []string{strings.TrimSpace(identity.PrivateKey), strings.TrimSpace(identity.PeerPublicKey)}
	for _, line := range strings.Split(cfg.UAPI, "\n") {
		if strings.HasPrefix(line, "private_key=") || strings.HasPrefix(line, "public_key=") {
			_, value, ok := strings.Cut(line, "=")
			if ok {
				redactions = append(redactions, value)
			}
		}
	}
	for _, secret := range redactions {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	return fmt.Errorf("start userspace WARP tunnel backend failed: %s", message)
}

type wireGuardNetstackBackend struct {
	device *device.Device
	net    *netstack.Net
}

func newWireGuardNetstackBackend(ctx context.Context, cfg RuntimeConfig) (backendDialer, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if len(cfg.InterfaceAddresses) == 0 {
		return nil, errors.New("wireguard interface address is required")
	}
	mtu := cfg.MTU
	if mtu == 0 {
		mtu = 1280
	}
	tun, tnet, err := netstack.CreateNetTUN(cfg.InterfaceAddresses, cfg.DNSServers, mtu)
	if err != nil {
		return nil, fmt.Errorf("create userspace netstack TUN: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err := dev.IpcSet(cfg.UAPI); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("start wireguard device: %w", err)
	}
	return &wireGuardNetstackBackend{device: dev, net: tnet}, nil
}

func (b *wireGuardNetstackBackend) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return b.net.DialContext(ctx, network, address)
}

func (b *wireGuardNetstackBackend) Close() error {
	if b == nil || b.device == nil {
		return nil
	}
	b.device.Close()
	return nil
}
