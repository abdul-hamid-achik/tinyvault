//go:build unix

package dotenv

import (
	"fmt"
	"os"
	"syscall"
)

func openParseTarget(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxFileSizeBytes {
		_ = file.Close()
		return nil, fmt.Errorf("%s exceeds the %d byte safety limit", path, maxFileSizeBytes)
	}

	return file, nil
}
