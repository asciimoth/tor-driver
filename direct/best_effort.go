package direct

import (
	"context"
	"sync"

	"github.com/asciimoth/gonnect"
	tor "github.com/asciimoth/tor-driver"
)

// BestEffortReport describes the host protections selected by
// NewBestEffortSystem. A nil Identity means that the child keeps the process's
// current operating-system identity. ContainmentError is non-nil when the
// strict platform containment adapter was unavailable and the system fell back
// to the ordinary process adapter.
//
// Best effort is not a security guarantee. Callers that require an external
// socket boundary must use NewContainedSystem directly and handle its error.
type BestEffortReport struct {
	// Identity is the configured child UID/GID. Nil means that the current OS
	// identity is retained. UID/GID identities are Linux-only.
	Identity *tor.Identity
	// AutomaticIdentity is true when the adapter selected Identity instead of
	// preserving an explicit Config.Identity.
	AutomaticIdentity bool
	// PrivilegeDrop is true when the Linux parent is root and the requested
	// child UID is nonzero. It describes the requested transition; Start still
	// reports any kernel failure.
	PrivilegeDrop bool
	// Containment is true when the strict platform adapter initialized.
	Containment bool
	// ContainmentError explains why the ordinary System adapter was selected.
	// It is nil when Containment is true.
	ContainmentError error
}

// BestEffortSystem is a native adapter that uses the strongest supported
// process protections available to the current process. It delegates to the
// strict platform ContainedSystem when that adapter can initialize. Otherwise,
// it uses System and records the reason in Report.
//
// The adapter is single-use when containment is active. Close is always safe
// to call and is required when a contained adapter was created but Driver did
// not start.
type BestEffortSystem struct {
	System
	processes   tor.Processes
	close       func() error
	report      BestEffortReport
	executables []executableDecision
	closeOnce   sync.Once
	logOnce     sync.Once
	closeErr    error
}

type executableDecision struct {
	name      string
	path      string
	automatic bool
}

// NewBestEffortSystem finds missing Tor and configured transport executables,
// then prepares automatic privilege reduction and platform containment.
// Explicit executable paths and Config.Identity take priority. On Linux, a
// root caller without an explicit identity uses the host's nobody account. A
// non-root caller keeps its current identity because it cannot safely change
// to another account.
//
// Failure to find an executable or a safe identity is an error. Inability to
// install optional containment is reported through Report and is not an error.
func NewBestEffortSystem(cfg tor.Config) (*BestEffortSystem, tor.Config, error) {
	resolved, err := FindExecutables(cfg)
	if err != nil {
		return nil, cfg, err
	}
	resolved, processes, closeProcess, report, err := prepareBestEffort(resolved)
	if err != nil {
		return nil, cfg, err
	}
	return &BestEffortSystem{
		processes:   processes,
		close:       closeProcess,
		report:      cloneBestEffortReport(report),
		executables: executableDecisions(cfg, resolved),
	}, resolved, nil
}

func executableDecisions(requested, resolved tor.Config) []executableDecision {
	decisions := make([]executableDecision, 0, 1+len(resolved.Transports))
	decisions = append(decisions, executableDecision{
		name:      "Tor",
		path:      resolved.TorExecutable,
		automatic: requested.TorExecutable == "",
	})
	for i, transport := range resolved.Transports {
		name := "managed transport " + string(transport.Kind)
		decisions = append(decisions, executableDecision{
			name:      name,
			path:      transport.Executable,
			automatic: i < len(requested.Transports) && requested.Transports[i].Executable == "",
		})
	}
	return decisions
}

// Report returns a copy of the selected security properties and any
// containment fallback error.
func (s *BestEffortSystem) Report() BestEffortReport {
	return cloneBestEffortReport(s.report)
}

func cloneBestEffortReport(report BestEffortReport) BestEffortReport {
	if report.Identity != nil {
		identity := *report.Identity
		report.Identity = &identity
	}
	return report
}

// Dependencies returns dependencies that use this adapter for filesystem,
// process, clock, and random operations. It logs all automatic and explicit
// preparation decisions once. Executable paths and UID/GID values are debug
// data. A containment fallback is also a warning because it changes the
// security boundary.
func (s *BestEffortSystem) Dependencies(local, outbound gonnect.Network, logger tor.Logger) tor.Dependencies {
	if logger != nil {
		s.logOnce.Do(func() {
			for _, executable := range s.executables {
				source := "explicit configuration"
				if executable.automatic {
					source = "PATH discovery"
				}
				logger.Debugf("direct: selected %s executable from %s: %q", executable.name, source, executable.path)
			}
			switch {
			case s.report.AutomaticIdentity:
				logger.Debugf("direct: will drop Linux root privileges to automatically selected UID %d GID %d", s.report.Identity.UID, s.report.Identity.GID)
			case s.report.Identity != nil && s.report.PrivilegeDrop:
				logger.Debugf("direct: will drop Linux root privileges to explicitly configured UID %d GID %d", s.report.Identity.UID, s.report.Identity.GID)
			case s.report.Identity != nil:
				logger.Debugf("direct: will request explicitly configured Linux UID %d GID %d", s.report.Identity.UID, s.report.Identity.GID)
			default:
				logger.Debug("direct: will keep the current operating-system identity")
			}
			switch {
			case s.report.Containment:
				logger.Debug("direct: selected strict platform process containment")
			case s.report.ContainmentError != nil:
				logger.Debug("direct: selected the ordinary process adapter after strict containment was unavailable")
				logger.Warnf("direct: automatic process containment unavailable; using ordinary process adapter: %v", s.report.ContainmentError)
			}
		})
	}
	deps := Dependencies(local, outbound, logger)
	deps.FS = s
	deps.Processes = s
	return deps
}

// Start launches through the selected process adapter.
func (s *BestEffortSystem) Start(ctx context.Context, spec tor.Launch) (tor.Process, error) {
	return s.processes.Start(ctx, spec)
}

// Close releases containment resources. It does nothing when the ordinary
// System adapter was selected.
func (s *BestEffortSystem) Close() error {
	s.closeOnce.Do(func() {
		if s.close != nil {
			s.closeErr = s.close()
		}
	})
	return s.closeErr
}

type managedProcesses interface {
	tor.Processes
	Close() error
}

func containedSelection(processes managedProcesses, report BestEffortReport) (tor.Processes, func() error, BestEffortReport) {
	report.Containment = true
	return processes, processes.Close, report
}

func fallbackSelection(err error, report BestEffortReport) (tor.Processes, func() error, BestEffortReport) {
	report.ContainmentError = err
	return System{}, nil, report
}

var _ tor.Processes = (*BestEffortSystem)(nil)
var _ interface{ Close() error } = (*BestEffortSystem)(nil)
