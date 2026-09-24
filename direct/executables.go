package direct

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"

	tor "github.com/asciimoth/tor-driver"
)

// FindExecutables returns a copy of cfg with missing executable paths found
// from the current process PATH. Explicit paths are not changed. A transport
// must already be present in cfg.Transports; discovery does not enable one.
func FindExecutables(cfg tor.Config) (tor.Config, error) {
	cfg.Transports = append([]tor.TransportConfig(nil), cfg.Transports...)

	if cfg.TorExecutable == "" {
		path, err := findExecutable("tor")
		if err != nil {
			return cfg, fmt.Errorf("direct: find Tor executable in PATH: %w", err)
		}
		cfg.TorExecutable = path
	}

	for i := range cfg.Transports {
		if cfg.Transports[i].Executable != "" {
			continue
		}
		switch cfg.Transports[i].Kind {
		case tor.Obfs4:
			path, err := findFirstExecutable("lyrebird", "obfs4proxy")
			if err != nil {
				return cfg, fmt.Errorf("direct: find obfs4 executable in PATH: %w", err)
			}
			cfg.Transports[i].Executable = path
		default:
			return cfg, tor.ErrUnsupportedTransport
		}
	}
	return cfg, nil
}

func findFirstExecutable(names ...string) (string, error) {
	var notFound error
	for _, name := range names {
		path, err := findExecutable(name)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, exec.ErrNotFound) {
			return "", err
		}
		notFound = err
	}
	if notFound != nil {
		return "", notFound
	}
	return "", exec.ErrNotFound
}

func findExecutable(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	return filepath.Abs(path)
}
