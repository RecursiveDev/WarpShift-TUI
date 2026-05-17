package warp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerateWireGuardProfileFromImportedIdentityAndConfig(t *testing.T) {
	identity, err := ImportManualIdentity(validManualIdentity())
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}
	profile, err := GenerateWireGuardProfile(*identity, WireGuardProfileConfig{
		AllowedIPs:          []string{"0.0.0.0/0", "::/0"},
		DNS:                 []string{"1.1.1.1", "1.0.0.1"},
		MTU:                 1280,
		PersistentKeepalive: 25,
	})
	if err != nil {
		t.Fatalf("GenerateWireGuardProfile returned unexpected error: %v", err)
	}

	for _, want := range []string{
		"[Interface]",
		"PrivateKey = " + identity.PrivateKey,
		"Address = 172.16.0.2/32, 2606:4700:110:abcd::2/128",
		"DNS = 1.1.1.1, 1.0.0.1",
		"MTU = 1280",
		"[Peer]",
		"PublicKey = " + identity.PeerPublicKey,
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"Endpoint = engage.cloudflareclient.com:2408",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("profile missing %q in:\n%s", want, profile)
		}
	}
	if strings.Contains(profile, identity.DeviceID) {
		t.Fatal("profile should not include local device metadata")
	}
}

func TestExportWireGuardProfileWritesSecureFile(t *testing.T) {
	identity, err := ImportManualIdentity(validManualIdentity())
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}
	path := filepath.Join(t.TempDir(), "warp.conf")

	if err := ExportWireGuardProfile(path, *identity, WireGuardProfileConfig{}); err != nil {
		t.Fatalf("ExportWireGuardProfile returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read exported profile: %v", err)
	}
	if !strings.Contains(string(data), "[Interface]") || !strings.Contains(string(data), "[Peer]") {
		t.Fatalf("exported profile missing required sections:\n%s", string(data))
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat exported profile: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("exported profile mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestGenerateWireGuardProfileRejectsIncompleteIdentity(t *testing.T) {
	identity := validManualIdentity()
	identity.PeerPublicKey = ""

	_, err := GenerateWireGuardProfile(Identity(identity), WireGuardProfileConfig{})
	if err == nil {
		t.Fatal("expected incomplete identity to be rejected")
	}
	if strings.Contains(err.Error(), identity.PrivateKey) {
		t.Fatalf("error leaked private key material: %v", err)
	}
}
