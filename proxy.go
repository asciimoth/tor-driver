package tordriver

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/asciimoth/gonnect"
)

type epoch struct {
	*scope
	network    gonnect.Network
	cleanup    []func()
	gate       *outboundGate
	generation uint64
}

type attachmentObserver struct {
	epoch *epoch
	gate  *outboundGate
}

func (o *attachmentObserver) Close() error {
	err := o.epoch.Close()
	o.gate.publish(OutboundEvent{Failure: OutboundAttachmentClosed, Generation: o.epoch.generation, Latched: true})
	return err
}

func (e *epoch) Up() error { return nil } // Explicit SetOutbound is required to rearm.
func (e *epoch) Down() error {
	err := e.Close()
	e.gate.publish(OutboundEvent{Failure: OutboundAttachmentClosed, Generation: e.generation, Latched: true})
	return err
}
func (e *epoch) IsUp() (bool, error) { return e.ctx.Err() == nil, nil }
func (e *epoch) retire() error {
	err := e.Close()
	for _, f := range e.cleanup {
		f()
	}
	return err
}

type outboundGate struct {
	mu            sync.Mutex
	change        sync.Mutex
	epoch         *epoch
	closed        bool
	generation    uint64
	attempts      atomic.Uint64
	failurePolicy OutboundFailurePolicy
	notify        func(OutboundEvent)
}

func (g *outboundGate) publish(event OutboundEvent) {
	if g.notify != nil {
		g.notify(event)
	}
}
func (g *outboundGate) failed(e *epoch, err error, failure OutboundFailure) {
	latched := errors.Is(err, net.ErrClosed) || (g.failurePolicy == LatchOutboundErrors && networkFailure(err))
	if latched {
		_ = e.Close()
	}
	g.publish(OutboundEvent{Failure: failure, Generation: e.generation, Latched: latched})
}
func (g *outboundGate) replace(n gonnect.Network) error {
	g.change.Lock()
	defer g.change.Unlock()
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return ErrClosed
	}
	old := g.epoch
	g.epoch = nil
	g.generation++
	g.mu.Unlock()
	if old != nil {
		if err := old.retire(); err != nil {
			g.publish(OutboundEvent{Failure: OutboundAttachmentRejected, Generation: g.generation, Latched: true})
			return err
		}
	}
	if n == nil {
		return nil
	}
	e := &epoch{scope: newScope(), network: n, gate: g, generation: g.generation}
	// Subscribe without gate/scope locks: already-closed networks can invoke
	// the callback synchronously. Retirement unregisters before reuse.
	if s, ok := n.(gonnect.CloserSubscriber); ok {
		observer := &attachmentObserver{epoch: e, gate: g}
		unsubscribe, err := s.SubscribeCloser(observer)
		if unsubscribe != nil {
			e.cleanup = append(e.cleanup, unsubscribe)
		}
		if err != nil {
			g.publish(OutboundEvent{Failure: OutboundAttachmentRejected, Generation: e.generation, Latched: true})
			return errors.Join(ErrOutboundUnavailable, err, e.retire())
		}
	}
	if s, ok := n.(gonnect.UpDownSubscriber); ok {
		unsubscribe, err := s.SubscribeUpDown(e)
		if unsubscribe != nil {
			e.cleanup = append(e.cleanup, unsubscribe)
		}
		if err != nil {
			g.publish(OutboundEvent{Failure: OutboundAttachmentRejected, Generation: e.generation, Latched: true})
			return errors.Join(ErrOutboundUnavailable, err, e.retire())
		}
	}
	if s, ok := n.(gonnect.UpDown); ok {
		up, err := s.IsUp()
		if err != nil || !up {
			g.publish(OutboundEvent{Failure: OutboundAttachmentRejected, Generation: e.generation, Latched: true})
			return errors.Join(ErrOutboundUnavailable, e.retire())
		}
	}
	if e.ctx.Err() != nil {
		g.publish(OutboundEvent{Failure: OutboundAttachmentRejected, Generation: e.generation, Latched: true})
		return errors.Join(ErrOutboundUnavailable, e.retire())
	}
	g.mu.Lock()
	g.epoch = e
	g.mu.Unlock()
	return nil
}
func (g *outboundGate) Close() error {
	g.change.Lock()
	defer g.change.Unlock()
	g.mu.Lock()
	g.closed = true
	e := g.epoch
	g.epoch = nil
	g.mu.Unlock()
	if e != nil {
		return e.retire()
	}
	return nil
}
func (g *outboundGate) state() OutboundState {
	g.mu.Lock()
	defer g.mu.Unlock()
	return OutboundState{Available: !g.closed && g.epoch != nil && g.epoch.ctx.Err() == nil, Generation: g.generation, Attempts: g.attempts.Load()}
}
func (g *outboundGate) dial(ctx context.Context, inc net.Conn, address string) (net.Conn, *epoch, error) {
	g.mu.Lock()
	e := g.epoch
	closed := g.closed
	g.mu.Unlock()
	if closed || e == nil || e.ctx.Err() != nil {
		return nil, nil, ErrOutboundUnavailable
	}
	in, err := e.add(inc)
	if err != nil {
		return nil, e, ErrOutboundUnavailable
	}
	// Caller closes inc. Remove this registration after session completion via
	// a wrapper around the outgoing connection, preserving both sides' lifetime.
	ctx, finish := e.operation(ctx)
	defer finish()
	if err = ctx.Err(); err != nil {
		_ = in.Close()
		return nil, e, err
	}
	g.attempts.Add(1)
	out, err := e.network.Dial(ctx, "tcp", address)
	if err != nil {
		if out != nil {
			_ = out.Close()
		}
		_ = in.Close()
		if ctx.Err() == nil {
			g.failed(e, err, OutboundDialFailed)
		}
		return nil, e, errors.Join(ErrOutboundUnavailable, err)
	}
	if out == nil {
		_ = in.Close()
		_ = e.Close()
		g.publish(OutboundEvent{Failure: OutboundDialFailed, Generation: e.generation, Latched: true})
		return nil, e, ErrOutboundUnavailable
	}
	tracked, err := e.track(out)
	if err != nil {
		_ = in.Close()
		return nil, e, ErrOutboundUnavailable
	}
	if ctx.Err() != nil {
		_ = tracked.Close()
		_ = in.Close()
		return nil, e, ctx.Err()
	}
	return &proxyPair{Conn: tracked, inc: in}, e, nil
}

type proxyPair struct {
	net.Conn
	inc *resource
}

func (p *proxyPair) Close() error { _ = p.inc.Close(); return p.Conn.Close() }

type proxyServer struct {
	listener       net.Listener
	scope          *scope
	gate           *outboundGate
	clock          Clock
	timeout        time.Duration
	user, password []byte
	limit          chan struct{}
	wg             sync.WaitGroup
	done           chan struct{}
	mu             sync.Mutex
	err            error
}

func startProxy(l net.Listener, g *outboundGate, c Clock, timeout time.Duration, max int, user, password string) *proxyServer {
	p := &proxyServer{listener: l, scope: newScope(), gate: g, clock: c, timeout: timeout, user: []byte(user), password: []byte(password), limit: make(chan struct{}, max), done: make(chan struct{})}
	go p.serve()
	return p
}
func (p *proxyServer) serve() {
	defer close(p.done)
	for {
		c, err := p.listener.Accept()
		if err != nil {
			p.mu.Lock()
			p.err = err
			p.mu.Unlock()
			return
		}
		select {
		case p.limit <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		tracked, err := p.scope.track(c)
		if err != nil {
			<-p.limit
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer func() { <-p.limit }()
			defer func() { _ = tracked.Close() }()
			p.handle(tracked)
		}()
	}
}
func (p *proxyServer) Close() error {
	err := errors.Join(p.scope.Close(), p.listener.Close())
	<-p.done
	p.wg.Wait()
	return err
}
func (p *proxyServer) handle(inc net.Conn) {
	ctx, cancel := p.clock.Timeout(p.scope.ctx, p.timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = inc.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := inc.SetDeadline(deadline); err != nil {
		return
	}
	if !p.authenticate(inc) {
		return
	}
	address, code := readConnect(inc)
	if code != 0 {
		replySOCKS(inc, code)
		return
	}
	out, e, err := p.gate.dial(ctx, inc, address)
	if err != nil {
		replySOCKS(inc, 1)
		return
	}
	defer func() { _ = out.Close() }()
	if !replySOCKS(inc, 0) {
		return
	}
	stop()
	if ctx.Err() != nil {
		return
	}
	if err = inc.SetDeadline(time.Time{}); err != nil {
		return
	}
	// Half-close where supported so request-body EOF does not discard a reply.
	results := make(chan error, 2)
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if cw, ok := unwrapProxy(dst).(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = dst.Close()
		}
		results <- err
	}
	go copyOne(out, inc)
	go copyOne(inc, out)
	err = <-results
	if err != nil {
		_ = out.Close()
		_ = inc.Close()
	}
	err2 := <-results
	// net.ErrClosed here commonly comes from closing this pair, and does not
	// establish that the shared Network has closed. Dial/notifications do that.
	if networkFailure(err) {
		p.gate.failed(e, err, OutboundStreamFailed)
	}
	if networkFailure(err2) {
		p.gate.failed(e, err2, OutboundStreamFailed)
	}
}
func unwrapProxy(c net.Conn) net.Conn {
	for {
		switch v := c.(type) {
		case *proxyPair:
			c = v.Conn
		case *ownedConn:
			c = v.Conn
		default:
			return c
		}
	}
}
func networkFailure(err error) bool {
	return err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, context.Canceled)
}
func (p *proxyServer) authenticate(c net.Conn) bool {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 5 || hdr[1] == 0 {
		return false
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return false
	}
	ok := false
	for _, m := range methods {
		ok = ok || m == 2
	}
	if !ok {
		_, _ = c.Write([]byte{5, 255})
		return false
	}
	if _, err := c.Write([]byte{5, 2}); err != nil {
		return false
	}
	if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 1 || hdr[1] == 0 {
		return false
	}
	user := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, user); err != nil {
		return false
	}
	var size [1]byte
	if _, err := io.ReadFull(c, size[:]); err != nil || size[0] == 0 {
		return false
	}
	password := make([]byte, int(size[0]))
	if _, err := io.ReadFull(c, password); err != nil {
		return false
	}
	ok = subtle.ConstantTimeCompare(user, p.user)&subtle.ConstantTimeCompare(password, p.password) == 1
	code := byte(1)
	if ok {
		code = 0
	}
	_, err := c.Write([]byte{1, code})
	return ok && err == nil
}
func readConnect(r io.Reader) (string, byte) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 1
	}
	if hdr[0] != 5 || hdr[2] != 0 {
		return "", 1
	}
	if hdr[1] != 1 {
		return "", 7
	}
	var addr netip.Addr
	switch hdr[3] {
	case 1:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 1
		}
		addr = netip.AddrFrom4(b)
	case 4:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return "", 1
		}
		addr = netip.AddrFrom16(b)
	default:
		return "", 8 // No domain resolution, BIND, UDP or protocol extensions.
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 1
	}
	a := netip.AddrPortFrom(addr, binary.BigEndian.Uint16(port[:]))
	if a.Port() == 0 || addr.IsUnspecified() {
		return "", 8
	}
	return a.String(), 0
}
func replySOCKS(c net.Conn, code byte) bool {
	_, err := c.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
	return err == nil
}
