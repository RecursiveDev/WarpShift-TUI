package app

import (
	"strings"
	"testing"
)

func TestNewRejectsEmptyName(t *testing.T) {
	_, err := New(Metadata{Name: "", Version: "dev"})
	if err == nil {
		t.Fatal("expected an error for an empty app name")
	}
}

func TestNewAppExposesMetadataAndSafeCapabilities(t *testing.T) {
	application, err := New(Metadata{Name: "WarpShift-TUI", Version: "dev"})
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}

	if application.Name() != "WarpShift-TUI" {
		t.Fatalf("Name() = %q, want %q", application.Name(), "WarpShift-TUI")
	}
	if application.Version() != "dev" {
		t.Fatalf("Version() = %q, want %q", application.Version(), "dev")
	}

	capabilities := strings.Join(application.SafeCapabilities(), "\n")
	for _, want := range []string{"CLI command surface", "TUI shell", "WARP status boundary", "local proxy boundary"} {
		if !strings.Contains(capabilities, want) {
			t.Fatalf("SafeCapabilities() missing %q in %q", want, capabilities)
		}
	}
}
