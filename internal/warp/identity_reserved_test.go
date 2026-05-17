package warp

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportManualIdentityExtractsReservedBytesFromClientID(t *testing.T) {
	manual := validManualIdentity()
	manual.ClientID = base64.RawURLEncoding.EncodeToString([]byte{7, 8, 9})

	identity, err := ImportManualIdentity(manual)
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}

	assertReservedBytes(t, identity.Reserved, []int{7, 8, 9})
}

func TestImportManualIdentityPersistsUserProvidedReservedBytes(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "identity.json")
	manual := validManualIdentity()
	manual.Reserved = []int{200, 201, 202}

	identity, err := ImportManualIdentity(manual)
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}
	if err := SaveIdentity(store, *identity); err != nil {
		t.Fatalf("SaveIdentity returned unexpected error: %v", err)
	}

	data, err := os.ReadFile(store)
	if err != nil {
		t.Fatalf("read stored identity: %v", err)
	}
	if !strings.Contains(string(data), `"reserved": [`) {
		t.Fatalf("stored identity should persist reserved bytes as a JSON array, got:\n%s", string(data))
	}
	loaded, err := LoadIdentity(store)
	if err != nil {
		t.Fatalf("LoadIdentity returned unexpected error: %v", err)
	}
	assertReservedBytes(t, loaded.Reserved, []int{200, 201, 202})
}

func TestImportManualIdentityRejectsInvalidReservedBytesWithoutEchoingInput(t *testing.T) {
	manual := validManualIdentity()
	manual.ClientID = "not-valid-client-id"

	_, err := ImportManualIdentity(manual)
	if err == nil {
		t.Fatal("expected invalid client_id to be rejected")
	}
	if strings.Contains(err.Error(), manual.ClientID) || strings.Contains(err.Error(), manual.PrivateKey) {
		t.Fatalf("error leaked supplied identity material: %v", err)
	}

	manual = validManualIdentity()
	manual.Reserved = []int{1, 2, 256}
	_, err = ImportManualIdentity(manual)
	if err == nil {
		t.Fatal("expected out-of-range reserved byte to be rejected")
	}
}

func TestGenerateWireGuardProfileIncludesReservedBytesWhenProvided(t *testing.T) {
	manual := validManualIdentity()
	manual.ClientID = base64.RawURLEncoding.EncodeToString([]byte{10, 11, 12})
	identity, err := ImportManualIdentity(manual)
	if err != nil {
		t.Fatalf("ImportManualIdentity returned unexpected error: %v", err)
	}

	profile, err := GenerateWireGuardProfile(*identity, WireGuardProfileConfig{})
	if err != nil {
		t.Fatalf("GenerateWireGuardProfile returned unexpected error: %v", err)
	}

	if !strings.Contains(profile, "Reserved = 10, 11, 12") {
		t.Fatalf("profile missing reserved bytes in:\n%s", profile)
	}
	if strings.Contains(profile, manual.ClientID) {
		t.Fatalf("profile leaked client_id: %q", profile)
	}
}

func assertReservedBytes(t *testing.T, got, want []int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("reserved bytes length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reserved bytes = %v, want %v", got, want)
		}
	}
}
