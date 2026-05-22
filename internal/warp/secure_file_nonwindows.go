//go:build !windows

package warp

import (
	"fmt"
	"os"
)

func replaceSecureFile(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace secure file: %w", err)
	}
	return nil
}
