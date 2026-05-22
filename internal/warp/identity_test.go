package warp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestImportManualIdentityFilePersistsSecurely(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "manual-identity.json")
	storePath := filepath.Join(dir, "identity.json")
	manual := validManualIdentity()
	data, err := json.Marshal(manual)
	if err != nil {
		t.Fatalf("marshal manual identity: %v", err)
	}
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatalf("write manual identity fixture: %v", err)
	}

	imported, err := ImportManualIdentityFile(sourcePath, storePath)
	if err != nil {
		t.Fatalf("ImportManualIdentityFile returned unexpected error: %v", err)
	}
	if imported.DeviceID != manual.DeviceID {
		t.Fatalf("device id = %q, want %q", imported.DeviceID, manual.DeviceID)
	}

	loaded, err := LoadIdentity(storePath)
	if err != nil {
		t.Fatalf("LoadIdentity returned unexpected error: %v", err)
	}
	if loaded.PrivateKey != manual.PrivateKey {
		t.Fatal("loaded identity did not preserve private key material")
	}
	if loaded.Endpoint != manual.Endpoint {
		t.Fatalf("endpoint = %q, want %q", loaded.Endpoint, manual.Endpoint)
	}

	info, err := os.Stat(storePath)
	if err != nil {
		t.Fatalf("stat stored identity: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("stored identity mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestLoadIdentityRejectsInsecurePermissionsOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACLs are platform-specific; LoadIdentity handles them best-effort")
	}

	path := filepath.Join(t.TempDir(), "identity.json")
	data, err := json.Marshal(validManualIdentity())
	if err != nil {
		t.Fatalf("marshal manual identity: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write identity fixture: %v", err)
	}

	_, err = LoadIdentity(path)
	if err == nil {
		t.Fatal("expected insecure identity permissions to be rejected")
	}
}

func TestLoadIdentityRejectsSymlinkOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}

	dir := t.TempDir()
	target := filepath.Join(dir, "target-identity.json")
	link := filepath.Join(dir, "identity.json")
	data, err := json.Marshal(validManualIdentity())
	if err != nil {
		t.Fatalf("marshal manual identity: %v", err)
	}
	if err := os.WriteFile(target, data, 0o600); err != nil {
		t.Fatalf("write identity target fixture: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create identity symlink fixture: %v", err)
	}

	_, err = LoadIdentity(link)
	if err == nil {
		t.Fatal("expected symlink identity path to be rejected")
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("LoadIdentity error = %q, want symlink rejection", err.Error())
	}
}

func TestImportManualIdentityRejectsIncompleteInputWithoutEchoingSecret(t *testing.T) {
	manual := validManualIdentity()
	manual.Endpoint = ""
	secret := manual.PrivateKey

	_, err := ImportManualIdentity(manual)
	if err == nil {
		t.Fatal("expected incomplete manual identity to be rejected")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked private key material: %v", err)
	}
}

func validManualIdentity() ManualIdentity {
	return ManualIdentity{
		DeviceID:           "manual-device-1",
		PrivateKey:         testPrivateKey(),
		InterfaceAddresses: []string{"172.16.0.2/32", "2606:4700:110:abcd::2/128"},
		PeerPublicKey:      "test-peer-public-key",
		Endpoint:           "engage.cloudflareclient.com:2408",
		DNS:                []string{"1.1.1.1", "1.0.0.1"},
	}
}

func testPrivateKey() string {
	parts := []string{"test", "manual", "wireguard", "key"}
	return strings.Join(parts, "-")
}
