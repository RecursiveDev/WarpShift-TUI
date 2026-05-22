//go:build windows

package warp

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8
)

var moveFileEx = moveFileExWindows

func replaceSecureFile(tmpPath, path string) error {
	if err := rejectSymlinkTarget(path); err != nil {
		return err
	}
	if err := moveFileEx(tmpPath, path); err != nil {
		return fmt.Errorf("replace secure file: %w", err)
	}
	return nil
}

func moveFileExWindows(tmpPath, path string) error {
	from, err := syscall.UTF16PtrFromString(tmpPath)
	if err != nil {
		return fmt.Errorf("encode temporary secure file path: %w", err)
	}
	to, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode secure file path: %w", err)
	}

	moveFileExW := syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")
	result, _, callErr := moveFileExW.Call(
		uintptr(unsafe.Pointer(from)),
		uintptr(unsafe.Pointer(to)),
		uintptr(moveFileReplaceExisting|moveFileWriteThrough),
	)
	if result == 0 {
		if callErr != syscall.Errno(0) {
			return callErr
		}
		return syscall.EINVAL
	}
	return nil
}
