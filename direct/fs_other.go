//go:build !linux

package direct

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	tor "github.com/asciimoth/tor-driver"
)

func securePrivateDir(path string, owner *tor.Identity) error {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		if err = os.MkdirAll(path, 0700); err != nil {
			return err
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("direct: expected a real directory")
	}
	if err = privatePermissions(path); err != nil {
		return err
	}
	if owner != nil {
		return os.Chown(path, int(owner.UID), int(owner.GID))
	}
	return nil
}

func secureWriteFile(path string, data []byte, mode fs.FileMode, owner *tor.Identity) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if err = errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	if owner != nil {
		return os.Chown(path, int(owner.UID), int(owner.GID))
	}
	return nil
}

func secureReadFile(path string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 1<<20 {
		return nil, fmt.Errorf("direct: invalid read limit")
	}
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("direct: invalid or oversized file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, fmt.Errorf("direct: oversized file")
	}
	return b, err
}

func secureRemoveAll(path string) error { return os.RemoveAll(path) }
