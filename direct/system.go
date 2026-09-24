// Package direct supplies native adapters for applications that do not need a
// virtual process/filesystem environment. Tor itself is installed separately.
package direct

import (
	"context"
	"crypto/rand"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

type System struct{}

func Dependencies(local, outbound gonnect.Network, logger tor.Logger) tor.Dependencies {
	s := System{}
	return tor.Dependencies{FS: s, Processes: s, Clock: s, Random: rand.Reader, Logger: logger, LocalNetwork: local, Outbound: outbound}
}

// Network creates a separate native gonnect instance. Call it independently
// for local networking and egress; core Driver never calls this constructor.
func Network() gonnect.Network  { return gonnect.NativeConfig{}.Build() }
func (System) PID() int         { return os.Getpid() }
func (System) Platform() string { return runtime.GOOS }
func (System) Now() time.Time   { return time.Now() }
func (System) Timeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, d)
}
func (System) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (System) TempDir(parent, pattern string) (string, error) {
	return secureTempDir(parent, pattern)
}
func (System) PrivateDir(path string, owner *tor.Identity) error {
	return securePrivateDir(path, owner)
}
func (System) WriteFile(path string, b []byte, mode fs.FileMode, owner *tor.Identity) error {
	return secureWriteFile(path, b, mode, owner)
}
func (System) ReadFile(path string, limit int64) ([]byte, error) {
	return secureReadFile(path, limit)
}
func (System) RemoveAll(path string) error { return secureRemoveAll(path) }
func (System) Start(ctx context.Context, spec tor.Launch) (tor.Process, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return startProcess(launchCommand(spec), spec.Identity)
}

func launchCommand(spec tor.Launch) *exec.Cmd {
	cmd := exec.Command(spec.Executable, spec.Args...)
	cmd.Dir = spec.Directory
	cmd.Stdout = spec.Stdout
	cmd.Stderr = spec.Stderr
	cmd.WaitDelay = 2 * time.Second
	// Do not inherit LD_PRELOAD, DYLD_*, TOR_PT_*, proxy variables or arbitrary
	// runtime configuration. PT binaries are configured by owned Tor itself.
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	for _, key := range []string{"PATH", "SystemRoot", "WINDIR", "TEMP", "TMP"} {
		if v, ok := os.LookupEnv(key); ok {
			cmd.Env = append(cmd.Env, key+"="+v)
		}
	}
	return cmd
}

type process struct {
	cmd     *exec.Cmd
	kill    func() error
	release func() error
	once    sync.Once
	err     error
}

func (p *process) Wait() error    { return p.cmd.Wait() }
func (p *process) Kill() error    { return p.kill() }
func (p *process) Release() error { p.once.Do(func() { p.err = p.release() }); return p.err }
