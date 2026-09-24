package direct

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	tor "github.com/asciimoth/tor-driver"
)

func TestFindExecutablesFindsTor(t *testing.T) {
	dir := t.TempDir()
	torPath := testExecutable(t, dir, "tor")
	t.Setenv("PATH", dir)

	cfg, err := FindExecutables(tor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TorExecutable != torPath {
		t.Fatalf("TorExecutable = %q, want %q", cfg.TorExecutable, torPath)
	}
	if !filepath.IsAbs(cfg.TorExecutable) {
		t.Fatalf("TorExecutable is not absolute: %q", cfg.TorExecutable)
	}
}

func TestFindExecutablesPreservesExplicitPaths(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	torPath := filepath.Join(string(filepath.Separator), "trusted", "tor")
	transportPath := filepath.Join(string(filepath.Separator), "trusted", "lyrebird")
	original := tor.Config{
		TorExecutable: torPath,
		Transports:    []tor.TransportConfig{{Kind: tor.Obfs4, Executable: transportPath}},
	}

	cfg, err := FindExecutables(original)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TorExecutable != torPath || cfg.Transports[0].Executable != transportPath {
		t.Fatalf("explicit paths changed: %#v", cfg)
	}

	cfg.Transports[0].Executable = "changed"
	if original.Transports[0].Executable != transportPath {
		t.Fatal("FindExecutables did not copy the transport slice")
	}
}

func TestFindExecutablesFindsObfs4Implementations(t *testing.T) {
	tests := []struct {
		name       string
		installed  []string
		wantBinary string
	}{
		{name: "prefer lyrebird", installed: []string{"obfs4proxy", "lyrebird"}, wantBinary: "lyrebird"},
		{name: "fall back to obfs4proxy", installed: []string{"obfs4proxy"}, wantBinary: "obfs4proxy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			torPath := testExecutable(t, dir, "tor")
			paths := make(map[string]string)
			for _, name := range test.installed {
				paths[name] = testExecutable(t, dir, name)
			}
			t.Setenv("PATH", dir)

			cfg, err := FindExecutables(tor.Config{Transports: []tor.TransportConfig{{Kind: tor.Obfs4}}})
			if err != nil {
				t.Fatal(err)
			}
			if cfg.TorExecutable != torPath {
				t.Fatalf("TorExecutable = %q, want %q", cfg.TorExecutable, torPath)
			}
			if got, want := cfg.Transports[0].Executable, paths[test.wantBinary]; got != want {
				t.Fatalf("transport executable = %q, want %q", got, want)
			}
		})
	}
}

func TestFindExecutablesDoesNotEnableTransports(t *testing.T) {
	dir := t.TempDir()
	testExecutable(t, dir, "tor")
	testExecutable(t, dir, "lyrebird")
	t.Setenv("PATH", dir)

	cfg, err := FindExecutables(tor.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Transports != nil {
		t.Fatalf("discovery enabled transports: %#v", cfg.Transports)
	}
}

func TestFindExecutablesReportsMissingBinaries(t *testing.T) {
	tests := []struct {
		name      string
		cfg       tor.Config
		installed []string
		message   string
	}{
		{name: "Tor", message: "find Tor executable"},
		{
			name:      "obfs4",
			cfg:       tor.Config{Transports: []tor.TransportConfig{{Kind: tor.Obfs4}}},
			installed: []string{"tor"},
			message:   "find obfs4 executable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range test.installed {
				testExecutable(t, dir, name)
			}
			t.Setenv("PATH", dir)

			_, err := FindExecutables(test.cfg)
			if !errors.Is(err, exec.ErrNotFound) {
				t.Fatalf("error = %v, want exec.ErrNotFound", err)
			}
			if !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %q, want text %q", err, test.message)
			}
		})
	}
}

func TestFindExecutablesRejectsUnknownMissingTransport(t *testing.T) {
	dir := t.TempDir()
	testExecutable(t, dir, "tor")
	t.Setenv("PATH", dir)

	_, err := FindExecutables(tor.Config{Transports: []tor.TransportConfig{{Kind: "unknown"}}})
	if !errors.Is(err, tor.ErrUnsupportedTransport) {
		t.Fatalf("error = %v, want ErrUnsupportedTransport", err)
	}
}

func testExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		name += ".exe"
		t.Setenv("PATHEXT", ".EXE")
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("test executable"), 0o755); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return abs
}
