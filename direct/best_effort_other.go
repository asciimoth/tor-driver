//go:build !linux && !windows

package direct

import (
	"fmt"

	tor "github.com/asciimoth/tor-driver"
)

func prepareBestEffort(cfg tor.Config) (tor.Config, tor.Processes, func() error, BestEffortReport, error) {
	processes, closeProcess, report := fallbackSelection(fmt.Errorf("direct: automatic containment: %w", tor.ErrUnsupported), BestEffortReport{})
	return cfg, processes, closeProcess, report, nil
}
