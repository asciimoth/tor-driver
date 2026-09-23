package tordriver

import (
	"context"
	"crypto/rand"
	"github.com/asciimoth/gonnect"
	"time"
)

type testClock struct{}

func (testClock) Now() time.Time { return time.Now() }
func (testClock) Timeout(c context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(c, d)
}
func (testClock) Sleep(c context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-c.Done():
		return c.Err()
	}
}
func testDriver(local gonnect.Network) *Driver {
	return &Driver{cfg: Config{DialTimeout: time.Second, CommandTimeout: time.Second, ShutdownTimeout: time.Second}, deps: Dependencies{Clock: testClock{}, Random: rand.Reader, Logger: NopLogger{}, LocalNetwork: local}, gate: &outboundGate{}, resources: newScope(), networks: make(map[*Network]struct{}), services: make(map[*Service]struct{}), keyNames: make(map[string]struct{}), events: newEventBroker[DriverEvent](), descriptors: make(map[string]PublicationEvent), processDone: make(chan struct{}), done: make(chan struct{}), socks: "127.0.0.1:19050"}
}
