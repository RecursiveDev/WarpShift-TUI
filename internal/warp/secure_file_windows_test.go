//go:build windows

package warp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReplaceSecureFileWindowsLeavesExistingFileWhenMoveFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "identity.json")
	tmp := filepath.Join(dir, ".warpshift-test.tmp")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatalf("write existing fixture: %v", err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatalf("write temporary fixture: %v", err)
	}

	originalMoveFileEx := moveFileEx
	moveFileEx = func(_, _ string) error { return errors.New("forced move failure") }
	t.Cleanup(func() { moveFileEx = originalMoveFileEx })

	err := replaceSecureFile(tmp, target)
	if err == nil {
		t.Fatal("expected forced replacement failure")
	}
	if !strings.Contains(err.Error(), "forced move failure") {
		t.Fatalf("replace error = %q, want forced failure", err.Error())
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read existing file after failed replacement: %v", err)
	}
	if string(data) != "old" {
		t.Fatalf("existing file changed after failed replacement: %q", data)
	}
	data, err = os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("temporary file should remain after failed replacement: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("temporary file changed after failed replacement: %q", data)
	}
}
