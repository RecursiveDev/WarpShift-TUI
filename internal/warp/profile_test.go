package warp

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProfileStoreImportListSwitchShowDeleteAndTraversalProtection(t *testing.T) {
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "manual.json")
	manual := validManualIdentity()
	manual.PrivateKey = "profile-secret-private-key"
	data, err := json.Marshal(manual)
	if err != nil {
		t.Fatalf("marshal profile fixture: %v", err)
	}
	if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}
	store, err := NewProfileStore(filepath.Join(dir, "profiles"))
	if err != nil {
		t.Fatalf("NewProfileStore returned unexpected error: %v", err)
	}

	imported, err := store.ImportManualIdentityFile("alpha", sourcePath)
	if err != nil {
		t.Fatalf("ImportManualIdentityFile returned unexpected error: %v", err)
	}
	if imported.PrivateKey != manual.PrivateKey {
		t.Fatal("imported profile did not preserve private key material")
	}
	profilePath, err := store.ProfileIdentityPath("alpha")
	if err != nil {
		t.Fatalf("ProfileIdentityPath returned unexpected error: %v", err)
	}
	info, err := os.Stat(profilePath)
	if err != nil {
		t.Fatalf("stat profile identity: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("profile identity mode = %v, want 0600", info.Mode().Perm())
	}

	profiles, err := store.ListProfiles()
	if err != nil {
		t.Fatalf("ListProfiles returned unexpected error: %v", err)
	}
	if len(profiles) != 1 || profiles[0].Name != "alpha" || profiles[0].Active {
		t.Fatalf("profiles = %#v, want inactive alpha", profiles)
	}
	if strings.Contains(profiles[0].Endpoint, manual.PrivateKey) {
		t.Fatal("profile summary leaked private key material")
	}

	loaded, err := store.LoadProfile("alpha")
	if err != nil {
		t.Fatalf("LoadProfile returned unexpected error: %v", err)
	}
	if loaded.Endpoint != manual.Endpoint {
		t.Fatalf("loaded profile endpoint = %q, want %q", loaded.Endpoint, manual.Endpoint)
	}
	if err := store.SwitchProfile("alpha"); err != nil {
		t.Fatalf("SwitchProfile returned unexpected error: %v", err)
	}
	active, err := store.ActiveProfile()
	if err != nil {
		t.Fatalf("ActiveProfile returned unexpected error: %v", err)
	}
	if active != "alpha" {
		t.Fatalf("active profile = %q, want alpha", active)
	}

	for _, name := range []string{"../escape", "nested/name", "..", ""} {
		if _, err := store.ProfileIdentityPath(name); !errors.Is(err, ErrInvalidProfileName) {
			t.Fatalf("ProfileIdentityPath(%q) error = %v, want ErrInvalidProfileName", name, err)
		}
	}
	if err := store.DeleteProfile("alpha"); err != nil {
		t.Fatalf("DeleteProfile returned unexpected error: %v", err)
	}
	if active, err := store.ActiveProfile(); err != nil || active != "" {
		t.Fatalf("active profile after delete = %q, err=%v; want empty", active, err)
	}
	if _, err := store.LoadProfile("alpha"); err == nil {
		t.Fatal("expected deleted profile load to fail")
	}
}
