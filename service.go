package tordriver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/tor-driver/internal/control"
)

// Service is a listen-only gonnect.Network for one ephemeral onion identity.
// Creation means registration with Tor, not descriptor publication. Clients
// should retry until reachable (see examples/onion-http).
// Closing any returned listener closes this entire service in the starter API.
type Service struct {
	rejected
	d            *Driver
	id           string
	scope        *scope
	registration *resource
	mu           sync.Mutex
	ports        map[uint16]*servicePort
	once         sync.Once
	err          error
}
type servicePort struct {
	listener net.Listener
	claimed  bool
}

var _ gonnect.Network = (*Service)(nil)

func (d *Driver) NewService(ctx context.Context, cfg ServiceConfig) (_ *Service, err error) {
	if d.cfg.Sandbox == LinuxSandbox {
		return nil, fmt.Errorf("tor-driver: dynamic onion services unavailable in LinuxSandbox mode")
	}
	if len(cfg.Ports) == 0 || len(cfg.Ports) > 128 {
		return nil, fmt.Errorf("tor-driver: supply 1 to 128 virtual ports")
	}
	s := &Service{d: d, scope: newScope(), ports: make(map[uint16]*servicePort)}
	for _, p := range cfg.Ports {
		if p == 0 {
			return nil, fmt.Errorf("tor-driver: zero virtual port")
		}
		if _, ok := s.ports[p]; ok {
			return nil, fmt.Errorf("tor-driver: duplicate virtual port")
		}
		s.ports[p] = &servicePort{}
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, ErrClosed
	}
	s.registration, err = d.resources.add(s.scope)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = s.registration.Close()
		}
	}()
	ctx, finish := s.scope.operation(ctx)
	defer finish()
	ctx, cancel := d.deps.Clock.Timeout(ctx, d.cfg.CommandTimeout)
	defer cancel()
	cmd := "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK"
	if cfg.MaxStreams > 0 {
		cmd += " MaxStreams=" + strconv.Itoa(int(cfg.MaxStreams))
	}
	for _, p := range cfg.Ports {
		l, e := d.deps.LocalNetwork.Listen(ctx, "tcp4", "127.0.0.1:0")
		if e != nil {
			return nil, e
		}
		if _, e = s.scope.add(l); e != nil {
			return nil, e
		}
		if _, e = numericEndpoint(l.Addr().String(), true); e != nil {
			return nil, e
		}
		s.ports[p].listener = l
		cmd += " Port=" + strconv.Itoa(int(p)) + "," + l.Addr().String()
	}
	r, err := d.command(ctx, cmd)
	if err != nil {
		var rejected *control.Error
		if !errors.As(err, &rejected) {
			_ = d.Close()
		}
		return nil, err
	}
	id, ok := control.Value(r, "ServiceID")
	if !ok || len(id) != 56 || strings.Trim(id, "abcdefghijklmnopqrstuvwxyz234567") != "" {
		// A successful but unidentifiable service cannot be deleted reliably.
		_ = d.Close()
		return nil, fmt.Errorf("tor-driver: invalid onion service response")
	}
	s.id = id
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, ErrClosed
	}
	d.services[s] = struct{}{}
	d.mu.Unlock()
	return s, nil
}
func (s *Service) Address() string { return s.id + ".onion" }
func (s *Service) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if !tcpNetwork(network) {
		return nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.scope.ctx.Err() != nil {
		return nil, ErrClosed
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host != "" && host != s.Address() {
		return nil, fmt.Errorf("tor-driver: service may only listen on its own onion address")
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return nil, fmt.Errorf("tor-driver: invalid virtual port")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.ports[uint16(p)]
	if !ok {
		return nil, fmt.Errorf("tor-driver: port was not reserved at service creation")
	}
	if b.claimed {
		return nil, fmt.Errorf("tor-driver: port already claimed")
	}
	b.claimed = true
	return &serviceListener{s: s, listener: b.listener, address: onionAddr(net.JoinHostPort(s.Address(), port))}, nil
}
func (s *Service) ListenTCP(ctx context.Context, network, address string) (gonnect.TCPListener, error) {
	l, err := s.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return l.(*serviceListener), nil
}
func (s *Service) Close() error {
	s.once.Do(func() {
		s.d.mu.Lock()
		closing := s.d.closed
		s.d.mu.Unlock()
		if !closing {
			_, s.err = s.d.command(context.Background(), "DEL_ONION "+s.id)
			// Never release the backing ports while a possibly-live mapping
			// remains in Tor. If deletion is ambiguous, stop the owned daemon.
			if s.err != nil {
				_ = s.d.Close()
			}
		}
		_ = s.registration.Close()
		s.d.mu.Lock()
		delete(s.d.services, s)
		s.d.mu.Unlock()
	})
	return s.err
}

type onionAddr string

func (a onionAddr) Network() string { return "tcp" }
func (a onionAddr) String() string  { return string(a) }

type serviceListener struct {
	s        *Service
	listener net.Listener
	address  onionAddr
}

func (l *serviceListener) Addr() net.Addr { return l.address }
func (l *serviceListener) Close() error   { return l.s.Close() }
func (l *serviceListener) Accept() (net.Conn, error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return l.s.scope.track(c)
}
func (l *serviceListener) AcceptTCP() (gonnect.TCPConn, error) {
	c, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpView{Conn: c}, nil
}
func (l *serviceListener) SetDeadline(t time.Time) error {
	if x, ok := l.listener.(interface{ SetDeadline(time.Time) error }); ok {
		return x.SetDeadline(t)
	}
	return ErrUnsupported
}

var _ gonnect.TCPListener = (*serviceListener)(nil)
