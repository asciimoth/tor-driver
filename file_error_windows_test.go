//go:build windows

package tordriver

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

type sharingViolationOnceFS struct {
	FileSystem
	failed bool
}

func (f *sharingViolationOnceFS) ReadFile(path string, limit int64) ([]byte, error) {
	if !f.failed {
		f.failed = true
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_SHARING_VIOLATION}
	}
	return f.FileSystem.ReadFile(path, limit)
}

func TestRetryableFileReadError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "sharing violation", err: windows.ERROR_SHARING_VIOLATION, want: true},
		{name: "wrapped lock violation", err: &os.PathError{Op: "open", Path: "control-port", Err: windows.ERROR_LOCK_VIOLATION}, want: true},
		{name: "permission", err: fs.ErrPermission, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := retryableFileReadError(test.err); got != test.want {
				t.Fatalf("retryableFileReadError() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestWaitFileRetriesWindowsSharingViolation(t *testing.T) {
	path := filepath.Join(`C:\work`, "control-port")
	base := &fixtureFS{files: map[string][]byte{path: []byte("PORT=127.0.0.1:9051\n")}}
	files := &sharingViolationOnceFS{FileSystem: base}
	driver := &Driver{
		deps:        Dependencies{FS: files, Clock: fixtureClock{}},
		processDone: make(chan struct{}),
	}

	data, err := driver.waitFile(context.Background(), path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "PORT=127.0.0.1:9051\n"; got != want {
		t.Fatalf("waitFile() = %q, want %q", got, want)
	}
}
