package warp

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// WireGuardProfileConfig contains non-secret profile export settings.
type WireGuardProfileConfig struct {
	AllowedIPs          []string
	DNS                 []string
	Endpoint            string
	MTU                 int
	PersistentKeepalive int
}

// GenerateWireGuardProfile renders a WireGuard profile from an imported identity.
func GenerateWireGuardProfile(identity Identity, cfg WireGuardProfileConfig) (string, error) {
	if err := validateIdentity(identity); err != nil {
		return "", err
	}
	cfg = fillProfileDefaults(identity, cfg)
	if err := validateProfileConfig(cfg); err != nil {
		return "", err
	}

	var builder strings.Builder
	builder.WriteString("[Interface]\n")
	builder.WriteString("PrivateKey = ")
	builder.WriteString(identity.PrivateKey)
	builder.WriteString("\n")
	builder.WriteString("Address = ")
	builder.WriteString(strings.Join(identity.InterfaceAddresses, ", "))
	builder.WriteString("\n")
	if len(cfg.DNS) > 0 {
		builder.WriteString("DNS = ")
		builder.WriteString(strings.Join(cfg.DNS, ", "))
		builder.WriteString("\n")
	}
	if cfg.MTU > 0 {
		builder.WriteString(fmt.Sprintf("MTU = %d\n", cfg.MTU))
	}
	if len(identity.Reserved) > 0 {
		builder.WriteString("Reserved = ")
		builder.WriteString(formatReservedBytes(identity.Reserved))
		builder.WriteString("\n")
	}
	builder.WriteString("\n[Peer]\n")
	builder.WriteString("PublicKey = ")
	builder.WriteString(identity.PeerPublicKey)
	builder.WriteString("\n")
	builder.WriteString("AllowedIPs = ")
	builder.WriteString(strings.Join(cfg.AllowedIPs, ", "))
	builder.WriteString("\n")
	builder.WriteString("Endpoint = ")
	builder.WriteString(cfg.Endpoint)
	builder.WriteString("\n")
	if cfg.PersistentKeepalive > 0 {
		builder.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", cfg.PersistentKeepalive))
	}
	return builder.String(), nil
}

func formatReservedBytes(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ", ")
}

// ExportWireGuardProfile writes a generated profile with restrictive permissions where supported.
func ExportWireGuardProfile(path string, identity Identity, cfg WireGuardProfileConfig) error {
	profile, err := GenerateWireGuardProfile(identity, cfg)
	if err != nil {
		return err
	}
	return writeSecureContent(path, []byte(profile))
}

func fillProfileDefaults(identity Identity, cfg WireGuardProfileConfig) WireGuardProfileConfig {
	if len(cfg.AllowedIPs) == 0 {
		cfg.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	if len(cfg.DNS) == 0 {
		cfg.DNS = identity.DNS
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = identity.Endpoint
	}
	if cfg.PersistentKeepalive == 0 {
		cfg.PersistentKeepalive = 25
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	return cfg
}

func validateProfileConfig(cfg WireGuardProfileConfig) error {
	for _, allowed := range cfg.AllowedIPs {
		if _, err := netip.ParsePrefix(allowed); err != nil {
			return fmt.Errorf("wireguard allowed IPs must be CIDR prefixes")
		}
	}
	for _, dns := range cfg.DNS {
		if _, err := netip.ParseAddr(dns); err != nil {
			return fmt.Errorf("wireguard DNS entries must be IP addresses")
		}
	}
	if err := validateHostPort(cfg.Endpoint); err != nil {
		return fmt.Errorf("wireguard endpoint: %w", err)
	}
	if cfg.PersistentKeepalive < 0 {
		return fmt.Errorf("wireguard persistent keepalive cannot be negative")
	}
	if cfg.MTU < 0 || (cfg.MTU > 0 && cfg.MTU < 576) {
		return fmt.Errorf("wireguard MTU must be at least 576 when set")
	}
	return nil
}

func writeSecureContent(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open secure file: %w", err)
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write secure file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close secure file: %w", closeErr)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			return fmt.Errorf("set secure file mode: %w", err)
		}
	}
	return nil
}
