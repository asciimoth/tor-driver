//go:build windows

package direct

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/windows"
)

func privateSecurityAttributes() (*windows.SecurityAttributes, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return nil, err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	return &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, nil
}

func createPrivateDirectory(path string, sa *windows.SecurityAttributes) (bool, error) {
	path16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	err = windows.CreateDirectory(path16, sa)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return false, nil
	}
	return err == nil, err
}

func securePrivateDir(path string, owner *tor.Identity) error {
	if owner != nil {
		return fmt.Errorf("direct: Linux UID/GID is not supported on Windows")
	}
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	if !filepath.IsAbs(path) || strings.EqualFold(path, root) {
		return fmt.Errorf("direct: private directory path must be absolute and not a root")
	}
	sa, err := privateSecurityAttributes()
	if err != nil {
		return err
	}
	relative := strings.TrimPrefix(path[len(volume):], string(filepath.Separator))
	current := root
	createdFinal := false
	for _, part := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, part)
		created, createErr := createPrivateDirectory(current, sa)
		if createErr != nil {
			return createErr
		}
		info, lstatErr := os.Lstat(current)
		if lstatErr != nil {
			return lstatErr
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("direct: expected a real directory")
		}
		createdFinal = created
	}
	// Existing final directories can have inherited entries. New directories
	// received the protected DACL in the CreateDirectory call.
	if !createdFinal {
		return privatePermissions(path)
	}
	return nil
}

func secureTempDir(parent, pattern string) (string, error) {
	if parent == "" {
		parent = os.TempDir()
	}
	if strings.ContainsAny(pattern, `/\\`) {
		return "", fmt.Errorf("direct: temporary directory pattern contains a path separator")
	}
	prefix, suffix := pattern, ""
	if index := strings.LastIndexByte(pattern, '*'); index >= 0 {
		prefix, suffix = pattern[:index], pattern[index+1:]
	}
	sa, err := privateSecurityAttributes()
	if err != nil {
		return "", err
	}
	for range 10000 {
		var random [8]byte
		if _, err = rand.Read(random[:]); err != nil {
			return "", err
		}
		path := filepath.Join(parent, prefix+hex.EncodeToString(random[:])+suffix)
		created, createErr := createPrivateDirectory(path, sa)
		if createErr == nil && created {
			return path, nil
		}
		if createErr != nil {
			return "", createErr
		}
	}
	return "", fmt.Errorf("direct: could not create a unique temporary directory")
}

func secureWriteFile(path string, data []byte, mode fs.FileMode, owner *tor.Identity) error {
	if owner != nil {
		return fmt.Errorf("direct: Linux UID/GID is not supported on Windows")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	return errors.Join(writeErr, closeErr)
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
