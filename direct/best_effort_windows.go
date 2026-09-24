//go:build windows

package direct

import (
	tor "github.com/asciimoth/tor-driver"
)

func prepareBestEffort(cfg tor.Config) (tor.Config, tor.Processes, func() error, BestEffortReport, error) {
	report := BestEffortReport{}
	executables := make([]string, 0, 1+len(cfg.Transports))
	executables = append(executables, cfg.TorExecutable)
	for _, transport := range cfg.Transports {
		executables = append(executables, transport.Executable)
	}
	contained, err := NewContainedSystem(WindowsContainmentConfig{Executables: executables})
	if err != nil {
		processes, closeProcess, fallbackReport := fallbackSelection(err, report)
		return cfg, processes, closeProcess, fallbackReport, nil
	}
	processes, closeProcess, containedReport := containedSelection(contained, report)
	return cfg, processes, closeProcess, containedReport, nil
}
