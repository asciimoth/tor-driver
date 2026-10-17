// Package debugtor wires the unsafe gobox debug backend for runnable examples.
// Production applications must supply a protected gobox backend instead.
package debugtor

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gobox/debug"
	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

type clock struct{}

func (clock) Now() time.Time { return time.Now() }
func (clock) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (clock) Timeout(ctx context.Context, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, duration)
}

type Runtime struct {
	Backend   *debug.Backend
	Sandboxes gobox.OwnerSandboxes
}

func New(ctx context.Context, executable, root, name string) (*Runtime, error) {
	if executable == "" {
		executable = "tor"
	}
	backend, err := debug.New(debug.Config{
		Root: root,
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
		return nil, err
	}
	owner := gobox.Owner{Workspace: "tor-driver-examples", Class: "example", Name: name}
	var ownerFile string
	if root != "" {
		if err = gobox.ValidateName(name); err != nil {
			_ = backend.Close()
			return nil, fmt.Errorf("invalid example owner name: %w", err)
		}
		ownerFile = filepath.Join(root, name+".owner.json")
		data, readErr := os.ReadFile(ownerFile)
		if readErr == nil {
			if err = json.Unmarshal(data, &owner); err != nil {
				_ = backend.Close()
				return nil, fmt.Errorf("read debug owner metadata: %w", err)
			}
		} else if !os.IsNotExist(readErr) {
			_ = backend.Close()
			return nil, readErr
		}
	}
	issued, sandboxes, err := backend.IssueAndBindOwner(ctx, owner)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	if ownerFile != "" && owner.Key == "" {
		data, marshalErr := json.Marshal(issued)
		if marshalErr != nil {
			_ = backend.Close()
			return nil, marshalErr
		}
		if err = os.WriteFile(ownerFile, data, 0600); err != nil {
			_ = backend.Close()
			return nil, err
		}
	}
	return &Runtime{Backend: backend, Sandboxes: sandboxes}, nil
}

func (runtime *Runtime) Dependencies(outbound gonnect.Network) tor.Dependencies {
	return tor.Dependencies{Sandboxes: runtime.Sandboxes, Clock: clock{}, Random: rand.Reader, Logger: tor.NopLogger{}, Outbound: outbound}
}

func Network() gonnect.Network { return gonnect.NativeConfig{}.Build() }

func (runtime *Runtime) Close() error { return runtime.Backend.Close() }
