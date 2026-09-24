//go:build linux

package direct

import (
	"context"
	"fmt"
)

// ContainmentStats reads the active Linux containment packet counters. It
// returns an error when best-effort setup selected the ordinary process
// adapter.
func (s *BestEffortSystem) ContainmentStats(ctx context.Context) (ContainmentStats, error) {
	contained, ok := s.processes.(*ContainedSystem)
	if !ok {
		return ContainmentStats{}, fmt.Errorf("direct: automatic containment is not active")
	}
	return contained.Stats(ctx)
}
