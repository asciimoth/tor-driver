//go:build linux

package direct

import (
	"fmt"
	"os"
	"os/user"
	"strconv"

	tor "github.com/asciimoth/tor-driver"
)

func prepareBestEffort(cfg tor.Config) (tor.Config, tor.Processes, func() error, BestEffortReport, error) {
	cfg, report, err := selectLinuxIdentity(cfg, os.Geteuid(), user.Lookup)
	if err != nil {
		return cfg, nil, nil, report, err
	}
	contained, containmentErr := NewContainedSystem(LinuxContainmentConfig{})
	if containmentErr != nil {
		processes, closeProcess, fallbackReport := fallbackSelection(containmentErr, report)
		return cfg, processes, closeProcess, fallbackReport, nil
	}
	processes, closeProcess, containedReport := containedSelection(contained, report)
	return cfg, processes, closeProcess, containedReport, nil
}

type lookupUserFunc func(string) (*user.User, error)

func selectLinuxIdentity(cfg tor.Config, effectiveUID int, lookup lookupUserFunc) (tor.Config, BestEffortReport, error) {
	report := BestEffortReport{}
	if cfg.Identity != nil {
		identity := *cfg.Identity
		cfg.Identity = &identity
		report.Identity = &identity
		report.PrivilegeDrop = effectiveUID == 0 && identity.UID != 0
		return cfg, report, nil
	}
	if effectiveUID != 0 {
		// An unprivileged process cannot switch to nobody. Leaving Identity nil
		// tells the adapter to retain the already-unprivileged current account.
		return cfg, report, nil
	}
	account, err := lookup("nobody")
	if err != nil {
		return cfg, report, fmt.Errorf("direct: find non-root nobody account: %w", err)
	}
	uid, uidErr := strconv.ParseUint(account.Uid, 10, 32)
	gid, gidErr := strconv.ParseUint(account.Gid, 10, 32)
	if uidErr != nil || gidErr != nil || uid == 0 || gid == 0 {
		return cfg, report, fmt.Errorf("direct: nobody account must have numeric non-root UID and GID")
	}
	identity := &tor.Identity{UID: uint32(uid), GID: uint32(gid)}
	cfg.Identity = identity
	report.Identity = &tor.Identity{UID: identity.UID, GID: identity.GID}
	report.AutomaticIdentity = true
	report.PrivilegeDrop = true
	return cfg, report, nil
}
