package tordriver

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
)

// scope rejects late acquisitions as well as closing existing resources.
type scope struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	items  map[*resource]struct{}
	done   chan struct{}
}
type resource struct {
	c    io.Closer
	s    *scope
	once sync.Once
	err  error
}

func newScope() *scope {
	ctx, cancel := context.WithCancel(context.Background())
	return &scope{ctx: ctx, cancel: cancel, items: make(map[*resource]struct{}), done: make(chan struct{})}
}
func (s *scope) add(c io.Closer) (*resource, error) {
	r := &resource{c: c, s: s}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = c.Close()
		return nil, ErrClosed
	}
	s.items[r] = struct{}{}
	s.mu.Unlock()
	return r, nil
}
func (r *resource) Close() error {
	r.once.Do(func() {
		r.s.mu.Lock()
		delete(r.s.items, r)
		r.s.mu.Unlock()
		r.err = r.c.Close()
	})
	return r.err
}
func (s *scope) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		<-s.done
		return nil
	}
	s.closed = true
	s.cancel()
	items := make([]*resource, 0, len(s.items))
	for r := range s.items {
		items = append(items, r)
	}
	s.mu.Unlock()
	for _, r := range items {
		_ = r.Close()
	}
	close(s.done)
	return nil
}
func (s *scope) operation(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	r, err := s.add(closerFunc(func() error {
		cancel()
		return nil
	}))
	if err != nil {
		cancel()
		return ctx, cancel
	}
	return ctx, func() { _ = r.Close() }
}
func (s *scope) track(c net.Conn) (*ownedConn, error) {
	r, err := s.add(c)
	if err != nil {
		return nil, err
	}
	return &ownedConn{Conn: c, resource: r}, nil
}

type ownedConn struct {
	net.Conn
	resource *resource
}

func (c *ownedConn) Close() error { return c.resource.Close() }

// tcpView retains lifecycle-aware Read/Write/Close and deliberately avoids
// exposing File/SyscallConn, which could escape close tracking.
type tcpView struct{ net.Conn }

func (c *tcpView) ReadFrom(r io.Reader) (int64, error) {
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}
func (c *tcpView) WriteTo(w io.Writer) (int64, error) { return io.Copy(w, struct{ io.Reader }{c.Conn}) }
func (c *tcpView) CloseRead() error {
	if v, ok := c.raw().(interface{ CloseRead() error }); ok {
		return v.CloseRead()
	}
	return ErrUnsupported
}
func (c *tcpView) CloseWrite() error {
	if v, ok := c.raw().(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return ErrUnsupported
}
func (c *tcpView) SetKeepAlive(v bool) error {
	if x, ok := c.raw().(interface{ SetKeepAlive(bool) error }); ok {
		return x.SetKeepAlive(v)
	}
	return ErrUnsupported
}
func (c *tcpView) SetKeepAliveConfig(v net.KeepAliveConfig) error {
	if x, ok := c.raw().(interface {
		SetKeepAliveConfig(net.KeepAliveConfig) error
	}); ok {
		return x.SetKeepAliveConfig(v)
	}
	return ErrUnsupported
}
func (c *tcpView) SetKeepAlivePeriod(v time.Duration) error {
	if x, ok := c.raw().(interface{ SetKeepAlivePeriod(time.Duration) error }); ok {
		return x.SetKeepAlivePeriod(v)
	}
	return ErrUnsupported
}
func (c *tcpView) SetLinger(v int) error {
	if x, ok := c.raw().(interface{ SetLinger(int) error }); ok {
		return x.SetLinger(v)
	}
	return ErrUnsupported
}
func (c *tcpView) SetNoDelay(v bool) error {
	if x, ok := c.raw().(interface{ SetNoDelay(bool) error }); ok {
		return x.SetNoDelay(v)
	}
	return ErrUnsupported
}
func (c *tcpView) raw() net.Conn {
	if v, ok := c.Conn.(*ownedConn); ok {
		return v.Conn
	}
	return c.Conn
}

var _ gonnect.TCPConn = (*tcpView)(nil)

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
