package tordriver

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
)

type dialNetwork struct {
	gonnect.RejectNetwork
	dial func(context.Context, string, string) (net.Conn, error)
}

func (n *dialNetwork) Dial(c context.Context, network, address string) (net.Conn, error) {
	return n.dial(c, network, address)
}
func TestGateBlocksAndLatchesErrors(t *testing.T) {
	g := &outboundGate{failurePolicy: LatchOutboundErrors}
	defer func() { _ = g.Close() }()
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	defer func() { _ = b.Close() }()
	if _, _, err := g.dial(context.Background(), a, "192.0.2.1:443"); !errors.Is(err, ErrOutboundUnavailable) {
		t.Fatal(err)
	}
	calls := 0
	n := &dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("backend failed")
	}}
	if err := g.replace(n); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, _, _ = g.dial(context.Background(), a, "192.0.2.1:443")
	}
	if calls != 1 || g.state().Available {
		t.Fatalf("failure not latched: calls=%d", calls)
	}
	if err := g.replace(n); err != nil {
		t.Fatal(err)
	}
	if !g.state().Available {
		t.Fatal("explicit rearm failed")
	}
}
func TestDefaultFailureRetriesOnlyInjectedNetwork(t *testing.T) {
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	calls := 0
	n := &dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		calls++
		return nil, errors.New("temporary backend failure")
	}}
	if err := g.replace(n); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		a, b := net.Pipe()
		_, _, err := g.dial(context.Background(), a, "192.0.2.1:443")
		_ = a.Close()
		_ = b.Close()
		if !errors.Is(err, ErrOutboundUnavailable) {
			t.Fatal(err)
		}
	}
	if calls != 2 || !g.state().Available {
		t.Fatalf("default retry policy: calls=%d available=%v", calls, g.state().Available)
	}
}
func TestReplacementDropsBothSidesAndLateDial(t *testing.T) {
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	started := make(chan struct{})
	release := make(chan struct{})
	out, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	var dialCtx context.Context
	n := &dialNetwork{dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialCtx = ctx
		close(started)
		<-release
		return out, nil
	}}
	if err := g.replace(n); err != nil {
		t.Fatal(err)
	}
	in, inPeer := net.Pipe()
	defer func() { _ = inPeer.Close() }()
	result := make(chan error, 1)
	go func() { _, _, err := g.dial(context.Background(), in, "192.0.2.1:443"); result <- err }()
	<-started
	if err := g.replace(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialCtx.Done():
	default:
		t.Fatal("old dial was not canceled")
	}
	assertClosed(t, inPeer)
	close(release)
	if err := <-result; err == nil {
		t.Fatal("late old-epoch connection accepted")
	}
	assertClosed(t, peer)
}
func TestReplacementClosesEstablishedPair(t *testing.T) {
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	out, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	_ = g.replace(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) { return out, nil }})
	in, inPeer := net.Pipe()
	defer func() { _ = inPeer.Close() }()
	c, _, err := g.dial(context.Background(), in, "192.0.2.1:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if err = g.replace(nil); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, peer)
	assertClosed(t, inPeer)
}

type closeErrorConn struct {
	net.Conn
	err error
}

func (c *closeErrorConn) Close() error {
	_ = c.Conn.Close()
	return c.err
}

func TestGateReportsConnectionCleanupFailure(t *testing.T) {
	want := errors.New("connection cleanup failed")
	g := &outboundGate{}
	out, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	if err := g.replace(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		return &closeErrorConn{Conn: out, err: want}, nil
	}}); err != nil {
		t.Fatal(err)
	}
	in, inPeer := net.Pipe()
	defer func() { _ = inPeer.Close() }()
	if _, _, err := g.dial(context.Background(), in, "192.0.2.1:443"); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); !errors.Is(err, want) {
		t.Fatalf("Close() error = %v, want cleanup error", err)
	}
}

func assertClosed(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err := c.Read(b[:])
	if err == nil {
		t.Fatal("connection still usable")
	}
	if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("connection remained open")
	}
}

type notifyingNetwork struct {
	dialNetwork
	mu     sync.Mutex
	closer io.Closer
}

func (n *notifyingNetwork) SubscribeCloser(c io.Closer) (func(), error) {
	n.mu.Lock()
	n.closer = c
	n.mu.Unlock()
	return func() { n.mu.Lock(); n.closer = nil; n.mu.Unlock() }, nil
}
func (n *notifyingNetwork) Close() error {
	n.mu.Lock()
	c := n.closer
	n.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}
func TestBackendCloseNotification(t *testing.T) {
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	n := &notifyingNetwork{}
	if err := g.replace(n); err != nil {
		t.Fatal(err)
	}
	_ = n.Close()
	if g.state().Available {
		t.Fatal("closed network left gate available")
	}
}

type synchronousNetwork struct {
	dialNetwork
	unsubscribed atomic.Int32
}

func (n *synchronousNetwork) SubscribeCloser(c io.Closer) (func(), error) {
	_ = c.Close()
	return func() { n.unsubscribed.Add(1) }, nil
}

func TestSynchronousCloseSubscription(t *testing.T) {
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	n := &synchronousNetwork{}
	if err := g.replace(n); !errors.Is(err, ErrOutboundUnavailable) {
		t.Fatalf("replace() error = %v", err)
	}
	if n.unsubscribed.Load() != 1 {
		t.Fatal("synchronous subscription was not removed")
	}
}

type racingSubscriber struct {
	dialNetwork
	mu     sync.Mutex
	closer io.Closer
}

func (n *racingSubscriber) SubscribeCloser(c io.Closer) (func(), error) {
	n.mu.Lock()
	n.closer = c
	n.mu.Unlock()
	return func() {
		n.mu.Lock()
		if n.closer == c {
			n.closer = nil
		}
		n.mu.Unlock()
	}, nil
}
func (n *racingSubscriber) notify() {
	n.mu.Lock()
	c := n.closer
	n.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
}

func TestSubscriptionNotificationAndUnsubscribeRace(t *testing.T) {
	g := &outboundGate{}
	n := &racingSubscriber{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = g.replace(n)
			_ = g.replace(nil)
		}()
		go func() {
			defer wg.Done()
			n.notify()
		}()
	}
	wg.Wait()
	_ = g.Close()
}

func TestConcurrentSetOutboundCloseAndDial(t *testing.T) {
	d := testDriver(&dialNetwork{})
	backend := &dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() { _ = b.Close() }()
		return a, nil
	}}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_ = d.SetOutbound(backend)
			_ = d.SetOutbound(nil)
		}()
		go func() {
			defer wg.Done()
			<-start
			in, peer := net.Pipe()
			out, _, _ := d.gate.dial(context.Background(), in, "192.0.2.1:443")
			if out != nil {
				_ = out.Close()
			}
			_ = in.Close()
			_ = peer.Close()
		}()
	}
	close(start)
	_ = d.Close()
	wg.Wait()
}

func TestProxyWireAuthenticationAndFailClosed(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := &outboundGate{}
	defer func() { _ = g.Close() }()
	seen := make(chan string, 1)
	n := &dialNetwork{dial: func(_ context.Context, network, address string) (net.Conn, error) {
		seen <- address
		a, b := net.Pipe()
		go func() { defer func() { _ = b.Close() }(); _, _ = io.Copy(b, b) }()
		return a, nil
	}}
	if err = g.replace(n); err != nil {
		t.Fatal(err)
	}
	p := startProxy(l, g, testClock{}, time.Second, 16, "u", "p")
	defer func() { _ = p.Close() }()
	client, err := socksgo.ClientFromURL("socks5://u:p@" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client.Filter = func(string, string) bool { return false }
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := client.Dial(ctx, "tcp", "192.0.2.10:443")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err = c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err = io.ReadFull(c, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	if address := <-seen; address != "192.0.2.10:443" {
		t.Fatal(address)
	}
	if err = g.replace(nil); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, c)
	if late, err := client.Dial(ctx, "tcp", "192.0.2.10:443"); err == nil {
		_ = late.Close()
		t.Fatal("blocked proxy accepted connection")
	}
	noAuth, _ := socksgo.ClientFromURL("socks5://" + l.Addr().String())
	noAuth.Filter = func(string, string) bool { return false }
	if c, err := noAuth.Dial(ctx, "tcp", "192.0.2.10:443"); err == nil {
		_ = c.Close()
		t.Fatal("unauthenticated client accepted")
	}
}
