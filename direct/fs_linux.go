//go:build linux

package direct

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/unix"
)

const secureResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS

func openDirectoryAt(parent int, name string, noMounts bool) (int, error) {
	resolve := uint64(secureResolve)
	if noMounts {
		resolve |= unix.RESOLVE_NO_XDEV
	}
	return unix.Openat2(parent, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: resolve,
	})
}

func splitAbsolute(path string) ([]string, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("direct: path must be absolute")
	}
	clean := filepath.Clean(path)
	if clean == string(filepath.Separator) {
		return nil, fmt.Errorf("direct: refusing filesystem root")
	}
	return strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)), nil
}

func openParent(path string) (int, string, error) {
	parts, err := splitAbsolute(path)
	if err != nil {
		return -1, "", err
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, "", err
	}
	for _, part := range parts[:len(parts)-1] {
		next, openErr := openDirectoryAt(fd, part, false)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, "", openErr
		}
		fd = next
	}
	return fd, parts[len(parts)-1], nil
}

func securePrivateDir(path string, owner *tor.Identity) error {
	parts, err := splitAbsolute(path)
	if err != nil {
		return err
	}
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range parts {
		next, openErr := openDirectoryAt(fd, part, false)
		if errors.Is(openErr, syscall.ENOENT) {
			if mkdirErr := unix.Mkdirat(fd, part, 0700); mkdirErr != nil && !errors.Is(mkdirErr, syscall.EEXIST) {
				return mkdirErr
			}
			next, openErr = openDirectoryAt(fd, part, false)
		}
		if openErr != nil {
			return fmt.Errorf("direct: open private directory: %w", openErr)
		}
		_ = unix.Close(fd)
		fd = next
	}
	if owner != nil {
		if err = unix.Fchown(fd, int(owner.UID), int(owner.GID)); err != nil {
			return err
		}
	}
	return unix.Fchmod(fd, 0700)
}

func secureWriteFile(path string, data []byte, mode fs.FileMode, owner *tor.Identity) (err error) {
	parent, name, err := openParent(path)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat(parent, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(mode.Perm()))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("direct: create file handle")
	}
	keep := false
	defer func() {
		closeErr := f.Close()
		if !keep {
			_ = unix.Unlinkat(parent, name, 0)
		}
		err = errors.Join(err, closeErr)
	}()
	if owner != nil {
		if err = unix.Fchown(fd, int(owner.UID), int(owner.GID)); err != nil {
			return err
		}
	}
	if err = unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return err
	}
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		return writeErr
	}
	keep = true
	return nil
}

func secureReadFile(path string, limit int64) ([]byte, error) {
	if limit < 1 || limit > 1<<20 {
		return nil, fmt.Errorf("direct: invalid read limit")
	}
	parent, name, err := openParent(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(parent) }()
	fd, err := unix.Openat2(parent, name, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK,
		Resolve: secureResolve,
	})
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("direct: open file handle")
	}
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size > limit {
		return nil, fmt.Errorf("direct: invalid or oversized file")
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, fmt.Errorf("direct: oversized file")
	}
	return b, err
}

func secureRemoveAll(path string) error {
	parent, name, err := openParent(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(parent) }()
	return removeAt(parent, name)
}

func removeAt(parent int, name string) error {
	fd, err := openDirectoryAt(parent, name, true)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP) {
		return unix.Unlinkat(parent, name, 0)
	}
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	if f == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("direct: open directory handle")
	}
	entries, readErr := f.ReadDir(-1)
	if readErr == nil {
		for _, entry := range entries {
			if err = removeAt(fd, entry.Name()); err != nil {
				break
			}
		}
	}
	closeErr := f.Close()
	if err = errors.Join(readErr, err, closeErr); err != nil {
		return err
	}
	return unix.Unlinkat(parent, name, unix.AT_REMOVEDIR)
}
