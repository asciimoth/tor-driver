//go:build e2e

package tordriver_test

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gobox/debug"
	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

type testClock struct{}

func (testClock) Now() time.Time { return time.Now() }
func (testClock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (testClock) Timeout(ctx context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, duration)
}

type testLogger struct{ t *testing.T }

func (logger testLogger) Debug(args ...any)                 { logger.t.Log(args...) }
func (logger testLogger) Debugf(format string, args ...any) { logger.t.Logf(format, args...) }
func (logger testLogger) Info(args ...any)                  { logger.t.Log(args...) }
func (logger testLogger) Infof(format string, args ...any)  { logger.t.Logf(format, args...) }
func (logger testLogger) Warn(args ...any)                  { logger.t.Log(args...) }
func (logger testLogger) Warnf(format string, args ...any)  { logger.t.Logf(format, args...) }
func (logger testLogger) Err(args ...any)                   { logger.t.Log(args...) }
func (logger testLogger) Errf(format string, args ...any)   { logger.t.Logf(format, args...) }
func (logger testLogger) Fatal(args ...any)                 { logger.t.Log(args...) }
func (logger testLogger) Fatalf(format string, args ...any) { logger.t.Logf(format, args...) }

func TestTorThroughDebugGoboxBackend(t *testing.T) {
	executable := os.Getenv("TOR_BINARY")
	if executable == "" {
		var err error
		executable, err = exec.LookPath("tor")
		if err != nil {
			t.Skip("real Tor not installed; set TOR_BINARY")
		}
	}
	backend, err := debug.New(debug.Config{
		Programs: map[gobox.ProgramID]debug.Program{
			tor.DefaultTorProgram: {
				Executable: executable,
				Arguments: func(launch gobox.Launch, resolve debug.ResolveValue) ([]string, error) {
					defaults, ok := launch.Inputs["defaults-torrc"]
					if !ok {
						return nil, fmt.Errorf("missing defaults-torrc")
					}
					torrc, ok := launch.Inputs["torrc"]
					if !ok {
						return nil, fmt.Errorf("missing torrc")
					}
					defaultsPath, err := resolve(defaults)
					if err != nil {
						return nil, err
					}
					torrcPath, err := resolve(torrc)
					if err != nil {
						return nil, err
					}
					return []string{"--defaults-torrc", defaultsPath, "-f", torrcPath}, nil
				},
			},
		},
		Templates: map[gobox.TemplateID]debug.Template{
			tor.DefaultSandboxTemplate: {Programs: []gobox.ProgramID{tor.DefaultTorProgram}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, sandboxes, err := backend.IssueAndBindOwner(ctx, gobox.Owner{Workspace: "tor-driver-tests", Class: "e2e", Name: t.Name()})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := tor.Start(ctx, tor.Config{}, tor.Dependencies{
		Sandboxes: sandboxes,
		Clock:     testClock{},
		Random:    rand.Reader,
		Logger:    testLogger{t},
		Outbound:  gonnect.NativeConfig{}.Build(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := driver.Close(); err != nil {
			t.Error(err)
		}
	})
	if err = driver.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
}
