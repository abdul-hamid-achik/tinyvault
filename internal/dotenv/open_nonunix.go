//go:build !unix

package dotenv

import (
	"fmt"
	"os"
)

func openParseTarget(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > maxFileSizeBytes {
		return nil, fmt.Errorf("%s exceeds the %d byte safety limit", path, maxFileSizeBytes)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	return file, nil
}
