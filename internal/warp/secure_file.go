package warp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

func writeSecureFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}
	if err := rejectSymlinkTarget(path); err != nil {
		return err
	}

	file, err := os.CreateTemp(dir, ".warpshift-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary secure file: %w", err)
	}
	tmpPath := file.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()

	if runtime.GOOS != "windows" {
		if err := file.Chmod(0o600); err != nil {
			_ = file.Close()
			return fmt.Errorf("set temporary secure file mode: %w", err)
		}
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("write secure file: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close secure file: %w", closeErr)
	}

	if err := replaceSecureFile(tmpPath, path); err != nil {
		return err
	}
	removeTemp = false
	return nil
}

func rejectSymlinkTarget(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat secure file target: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refuse to overwrite symlink: %s", path)
	}
	if info.IsDir() {
		return fmt.Errorf("refuse to overwrite directory: %s", path)
	}
	return nil
}
