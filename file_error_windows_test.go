//go:build windows

package tordriver

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/asciimoth/gobox"
	"golang.org/x/sys/windows"
)

type sharingViolationOnceFS struct {
	gobox.Files
	failed bool
}

func (f *sharingViolationOnceFS) ReadFile(ctx context.Context, path string, limit int64) ([]byte, error) {
	if !f.failed {
		f.failed = true
		return nil, &os.PathError{Op: "open", Path: path, Err: windows.ERROR_SHARING_VIOLATION}
	}
	return f.Files.ReadFile(ctx, path, limit)
}

type sharingViolationSandbox struct {
	gobox.Sandbox
	files gobox.Files
}

func (s *sharingViolationSandbox) FS(gobox.Root) (gobox.Files, error) { return s.files, nil }

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
	nativePath := filepath.Join(`C:\work`, "control-port")
	base := &fixtureFS{root: `C:\work`, files: map[string][]byte{nativePath: []byte("PORT=127.0.0.1:9051\n")}}
	baseSandbox := &fixtureSandbox{fs: base}
	files := &sharingViolationOnceFS{Files: &fixtureFiles{box: baseSandbox, root: gobox.Temporary}}
	driver := &Driver{
		deps:        Dependencies{Clock: fixtureClock{}},
		box:         &sharingViolationSandbox{Sandbox: baseSandbox, files: files},
		processDone: make(chan struct{}),
	}

	data, err := driver.waitFile(context.Background(), gobox.Path{Root: gobox.Temporary, Rel: "work/control-port"}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), "PORT=127.0.0.1:9051\n"; got != want {
		t.Fatalf("waitFile() = %q, want %q", got, want)
	}
}
