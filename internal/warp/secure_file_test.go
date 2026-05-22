package warp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteSecureFileAtomicRejectsSymlinkTarget(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	outside := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside fixture: %v", err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatalf("create symlink fixture: %v", err)
	}

	err := writeSecureFileAtomic(target, []byte("secret\n"))
	if err == nil {
		t.Fatal("expected symlink target to be rejected")
	}
	if !strings.Contains(err.Error(), "refuse to overwrite symlink") {
		t.Fatalf("symlink error = %q", err.Error())
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatalf("read outside fixture: %v", err)
	}
	if string(data) != "outside" {
		t.Fatalf("symlink target was modified: %q", data)
	}
}

func TestWriteSecureFileAtomicReplacesRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("write old fixture: %v", err)
	}
	if err := writeSecureFileAtomic(path, []byte("new\n")); err != nil {
		t.Fatalf("writeSecureFileAtomic returned error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if string(data) != "new\n" {
		t.Fatalf("replaced content = %q", data)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat replaced file: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("file mode = %o, want 0600", got)
		}
	}
}
