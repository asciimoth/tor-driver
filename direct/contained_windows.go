//go:build windows

package direct

import (
	"context"
	"fmt"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

// WindowsContainmentConfig is retained for API compatibility. Executable-path
// firewall rules cannot contain descendant processes, so strict Windows
// containment is unavailable.
type WindowsContainmentConfig struct {
	Executables          []string
	PowerShellExecutable string
}

// ContainedSystem is an unavailable strict Windows Process adapter. The zero
// value also fails closed if it is constructed without NewContainedSystem.
type ContainedSystem struct{}

// NewContainedSystem fails closed on Windows. Windows Firewall program rules
// apply to an executable path, not to a Job Object process tree. A child can
// therefore run another image path and bypass those rules. Use an external
// sandbox that gives the complete process tree one enforceable network identity.
func NewContainedSystem(WindowsContainmentConfig) (*ContainedSystem, error) {
	return nil, fmt.Errorf("direct: strict Windows process containment is unavailable because executable-scoped firewall rules do not contain descendants: %w", tor.ErrUnsupported)
}

// Dependencies returns dependencies that keep the unavailable adapter in the
// process position. Start will return ErrUnsupported without launching a child.
func (s *ContainedSystem) Dependencies(local, outbound gonnect.Network, logger tor.Logger) tor.Dependencies {
	deps := Dependencies(local, outbound, logger)
	deps.Processes = s
	return deps
}

// Start fails without launching a process.
func (*ContainedSystem) Start(context.Context, tor.Launch) (tor.Process, error) {
	return nil, fmt.Errorf("direct: strict Windows process containment: %w", tor.ErrUnsupported)
}

// Close has no resources to release.
func (*ContainedSystem) Close() error { return nil }

func (*ContainedSystem) PID() int         { return System{}.PID() }
func (*ContainedSystem) Platform() string { return System{}.Platform() }

var _ tor.Processes = (*ContainedSystem)(nil)
