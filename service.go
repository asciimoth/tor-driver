package tordriver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/tor-driver/internal/control"
)

// Service is a listen-only gonnect.Network for one v3 onion identity.
// WaitPublished waits for a descriptor upload. Closing a returned listener
// removes only that virtual port; the reserved port can be reopened.
type Service struct {
	rejected
	d            *Driver
	id           string
	key          OnionServiceKey
	keyName      string
	cfg          ServiceConfig
	scope        *scope
	registration *resource
	events       *eventBroker[ServiceEvent]

	mu        sync.Mutex
	ports     map[uint16]*servicePort
	active    bool
	closing   bool
	closingCh chan struct{}
	once      sync.Once
	err       error

	publicationMu      sync.Mutex
	publication        PublicationEvent
	publicationChanged chan struct{}

	acceptedMu      sync.Mutex
	accepted        map[*serviceConn]struct{}
	accepting       int
	stopping        bool
	acceptedChanged chan struct{}
}

type servicePort struct {
	listener   net.Listener
	resource   *resource
	claimed    bool
	generation uint64
}

var _ gonnect.Network = (*Service)(nil)
var _ gonnect.CloserSubscriber = (*Service)(nil)

func (d *Driver) NewService(ctx context.Context, cfg ServiceConfig) (_ *Service, err error) {
	if d.cfg.Sandbox == LinuxSandbox {
		return nil, fmt.Errorf("tor-driver: dynamic onion services unavailable in LinuxSandbox mode")
	}
	if len(cfg.Ports) == 0 || len(cfg.Ports) > 128 {
		return nil, fmt.Errorf("tor-driver: supply 1 to 128 virtual ports")
	}
	if cfg.MaxStreamsPolicy > CloseRendezvousCircuit || (cfg.MaxStreamsPolicy == CloseRendezvousCircuit && cfg.MaxStreams == 0) {
		return nil, fmt.Errorf("tor-driver: invalid maximum stream policy")
	}
	if cfg.KeyName != "" {
		if !validKeyName(cfg.KeyName) {
			return nil, fmt.Errorf("tor-driver: invalid onion key name")
		}
		if d.deps.OnionKeys == nil {
			return nil, fmt.Errorf("tor-driver: a named service requires OnionKeys")
		}
	}
	clients := make([]ClientAuthorizationPublicKey, len(cfg.AuthorizedClients))
	copy(clients, cfg.AuthorizedClients)
	seenClients := make(map[string]struct{}, len(clients))
	for i, client := range clients {
		encoded, encodeErr := client.MarshalText()
		if encodeErr != nil {
			return nil, fmt.Errorf("tor-driver: authorized client %d: %w", i, encodeErr)
		}
		if _, ok := seenClients[string(encoded)]; ok {
			return nil, fmt.Errorf("tor-driver: duplicate authorized client")
		}
		seenClients[string(encoded)] = struct{}{}
	}
	cfg.Ports = append([]uint16(nil), cfg.Ports...)
	cfg.AuthorizedClients = clients
	s := &Service{
		d: d, keyName: cfg.KeyName, cfg: cfg, scope: newScope(),
		events: newEventBroker[ServiceEvent](), ports: make(map[uint16]*servicePort),
		closingCh:   make(chan struct{}),
		publication: PublicationEvent{State: PublicationPending}, publicationChanged: make(chan struct{}),
		accepted: make(map[*serviceConn]struct{}), acceptedChanged: make(chan struct{}),
	}
	if _, err = s.scope.add(closerFunc(func() error { s.events.close(); return nil })); err != nil {
		return nil, err
	}
	for _, port := range cfg.Ports {
		if port == 0 {
			return nil, fmt.Errorf("tor-driver: zero virtual port")
		}
		if _, ok := s.ports[port]; ok {
			return nil, fmt.Errorf("tor-driver: duplicate virtual port")
		}
		s.ports[port] = &servicePort{}
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		_ = s.scope.Close()
		return nil, ErrClosed
	}
	if cfg.KeyName != "" {
		if _, exists := d.keyNames[cfg.KeyName]; exists {
			d.mu.Unlock()
			_ = s.scope.Close()
			return nil, fmt.Errorf("tor-driver: onion key name is already active")
		}
		d.keyNames[cfg.KeyName] = struct{}{}
	}
	s.registration, err = d.resources.add(s.scope)
	d.mu.Unlock()
	if err != nil {
		d.mu.Lock()
		delete(d.keyNames, cfg.KeyName)
		d.mu.Unlock()
		return nil, err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.registration.Close())
			d.mu.Lock()
			delete(d.keyNames, cfg.KeyName)
			d.mu.Unlock()
		}
	}()

	ctx, finish := s.scope.operation(ctx)
	defer finish()
	generated := true
	if cfg.KeyName != "" {
		s.key, err = d.deps.OnionKeys.Load(ctx, cfg.KeyName)
		switch {
		case err == nil:
			if !s.key.valid() {
				return nil, fmt.Errorf("tor-driver: key store returned an invalid onion service key")
			}
			generated = false
		case errors.Is(err, fs.ErrNotExist):
			err = nil
		default:
			return nil, err
		}
	}
	for _, port := range cfg.Ports {
		binding, bindErr := s.newBacking(ctx)
		if bindErr != nil {
			return nil, bindErr
		}
		s.ports[port] = binding
	}
	reply, err := s.addOnion(ctx, generated, s.currentMappingsLocked())
	if err != nil {
		var rejected *control.Error
		if !errors.As(err, &rejected) {
			_ = d.Close()
		}
		return nil, err
	}
	if err = s.applyAddReply(reply, generated, ""); err != nil {
		_ = d.Close()
		return nil, err
	}
	s.active = true
	if generated && cfg.KeyName != "" {
		if err = d.deps.OnionKeys.Store(ctx, cfg.KeyName, s.key); err != nil {
			_, deleteErr := d.command(context.Background(), "DEL_ONION "+s.id)
			if deleteErr != nil {
				_ = d.Close()
			}
			return nil, joinDeleteError(err, deleteErr)
		}
	}
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil, ErrClosed
	}
	d.services[s] = struct{}{}
	cached, haveCached := d.descriptors[s.id]
	d.mu.Unlock()
	if haveCached {
		s.handlePublication(cached)
	}
	return s, nil
}

func (s *Service) newBacking(ctx context.Context) (*servicePort, error) {
	listener, err := s.d.deps.LocalNetwork.Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	if _, err = numericEndpoint(listener.Addr().String(), true); err != nil {
		_ = listener.Close()
		return nil, err
	}
	resource, err := s.scope.add(listener)
	if err != nil {
		return nil, err
	}
	return &servicePort{listener: listener, resource: resource, generation: 1}, nil
}

func (s *Service) currentMappingsLocked() map[uint16]*servicePort {
	mappings := make(map[uint16]*servicePort)
	for port, binding := range s.ports {
		if binding.listener != nil {
			mappings[port] = binding
		}
	}
	return mappings
}

func (s *Service) addOnion(ctx context.Context, generated bool, mappings map[uint16]*servicePort) (control.Reply, error) {
	key := "ED25519-V3:" + s.key.torBlob()
	if generated {
		key = "NEW:ED25519-V3"
	}
	command := "ADD_ONION " + key
	var flags []string
	if len(s.cfg.AuthorizedClients) > 0 {
		flags = append(flags, "V3Auth")
	}
	if s.cfg.MaxStreamsPolicy == CloseRendezvousCircuit {
		flags = append(flags, "MaxStreamsCloseCircuit")
	}
	if len(flags) > 0 {
		command += " Flags=" + strings.Join(flags, ",")
	}
	if s.cfg.MaxStreams > 0 {
		command += " MaxStreams=" + strconv.Itoa(int(s.cfg.MaxStreams))
	}
	for _, client := range s.cfg.AuthorizedClients {
		encoded, _ := client.MarshalText()
		command += " ClientAuthV3=" + string(encoded)
	}
	ports := make([]int, 0, len(mappings))
	for port := range mappings {
		ports = append(ports, int(port))
	}
	sort.Ints(ports)
	for _, value := range ports {
		binding := mappings[uint16(value)]
		command += " Port=" + strconv.Itoa(value) + "," + binding.listener.Addr().String()
	}
	return s.d.command(ctx, command)
}

func (s *Service) applyAddReply(reply control.Reply, generated bool, expectedID string) error {
	id, ok := control.Value(reply, "ServiceID")
	if !ok || !validServiceID(id) || (expectedID != "" && id != expectedID) {
		return fmt.Errorf("tor-driver: invalid onion service response")
	}
	if generated {
		encoded, found := control.Value(reply, "PrivateKey")
		if !found {
			return fmt.Errorf("tor-driver: Tor did not return the generated onion service key")
		}
		key, parseErr := ParseOnionServiceKey([]byte(encoded))
		if parseErr != nil {
			return parseErr
		}
		s.key = key
	}
	s.id = id
	return nil
}

func (s *Service) Address() string { return s.id + ".onion" }

func (s *Service) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if !tcpNetwork(network) {
		return nil, ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	port, err := s.virtualPort(address)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.scope.ctx.Err() != nil {
		return nil, ErrClosed
	}
	binding := s.ports[port]
	if binding.claimed {
		return nil, fmt.Errorf("tor-driver: port already claimed")
	}
	if binding.listener == nil {
		candidate, createErr := s.newBacking(ctx)
		if createErr != nil {
			return nil, createErr
		}
		desired := s.currentMappingsLocked()
		desired[port] = candidate
		if createErr = s.replaceMappingsLocked(ctx, desired); createErr != nil {
			_ = candidate.resource.Close()
			return nil, createErr
		}
		candidate.generation = binding.generation + 1
		s.ports[port] = candidate
		binding = candidate
	}
	binding.claimed = true
	return &serviceListener{
		s: s, port: port, generation: binding.generation, listener: binding.listener,
		address: onionAddr(net.JoinHostPort(s.Address(), strconv.Itoa(int(port)))),
	}, nil
}

func (s *Service) virtualPort(address string) (uint16, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return 0, err
	}
	if host != "" && host != s.Address() {
		return 0, fmt.Errorf("tor-driver: service may only listen on its own onion address")
	}
	value, err := strconv.ParseUint(port, 10, 16)
	if err != nil || value == 0 {
		return 0, fmt.Errorf("tor-driver: invalid virtual port")
	}
	if _, ok := s.ports[uint16(value)]; !ok {
		return 0, fmt.Errorf("tor-driver: port was not reserved at service creation")
	}
	return uint16(value), nil
}

func (s *Service) ListenTCP(ctx context.Context, network, address string) (gonnect.TCPListener, error) {
	listener, err := s.Listen(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return listener.(*serviceListener), nil
}

// RemovePort withdraws one reserved virtual port. Tor acknowledges the new
// mapping before the old backing listener is released. Listen can reopen it.
func (s *Service) RemovePort(ctx context.Context, port uint16) error {
	return s.removePort(ctx, port, 0)
}

func (s *Service) removePort(ctx context.Context, port uint16, generation uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.scope.ctx.Err() != nil {
		return ErrClosed
	}
	binding, ok := s.ports[port]
	if !ok {
		return fmt.Errorf("tor-driver: port was not reserved at service creation")
	}
	if binding.listener == nil || (generation != 0 && binding.generation != generation) {
		return nil
	}
	desired := s.currentMappingsLocked()
	delete(desired, port)
	if err := s.replaceMappingsLocked(ctx, desired); err != nil {
		return err
	}
	err := binding.resource.Close()
	binding.listener = nil
	binding.resource = nil
	binding.claimed = false
	binding.generation++
	return err
}

func (s *Service) replaceMappingsLocked(ctx context.Context, desired map[uint16]*servicePort) error {
	old := s.currentMappingsLocked()
	wasActive := s.active
	if wasActive {
		if _, err := s.d.command(ctx, "DEL_ONION "+s.id); err != nil {
			_ = s.d.Close()
			return err
		}
		s.active = false
	}
	s.resetPublication()
	if len(desired) == 0 {
		return nil
	}
	reply, err := s.addOnion(ctx, false, desired)
	if err == nil {
		err = s.applyAddReply(reply, false, s.id)
	}
	if err == nil {
		s.active = true
		return nil
	}
	var rejected *control.Error
	if !errors.As(err, &rejected) {
		_ = s.d.Close()
		return err
	}
	if wasActive {
		rollback, rollbackErr := s.addOnion(context.Background(), false, old)
		if rollbackErr == nil {
			rollbackErr = s.applyAddReply(rollback, false, s.id)
		}
		if rollbackErr == nil {
			s.active = true
		} else {
			_ = s.d.Close()
		}
		return errors.Join(err, rollbackErr)
	}
	return err
}

// SubscribeEvents returns descriptor publication events for this service.
func (s *Service) SubscribeEvents(buffer int) (<-chan ServiceEvent, func(), error) {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		return nil, nil, ErrClosed
	}
	s.publicationMu.Lock()
	current := s.publication
	ch, cancel, err := s.events.subscribeInitial(buffer, ServiceEvent(current), true)
	s.publicationMu.Unlock()
	s.mu.Unlock()
	if err != nil {
		return nil, nil, err
	}
	return ch, cancel, nil
}

// WaitPublished waits until Tor confirms at least one descriptor upload for
// the current mapping. A failed upload to one directory does not end the wait.
func (s *Service) WaitPublished(ctx context.Context) error {
	for {
		select {
		case <-s.closingCh:
			return ErrClosed
		default:
		}
		s.publicationMu.Lock()
		if s.publication.State == PublicationPublished {
			s.publicationMu.Unlock()
			return nil
		}
		changed := s.publicationChanged
		s.publicationMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.closingCh:
			return ErrClosed
		case <-s.scope.ctx.Done():
			return ErrClosed
		case <-changed:
		}
	}
}

func (s *Service) handlePublication(event PublicationEvent) {
	s.publicationMu.Lock()
	if s.publication.State == PublicationPublished && event.State != PublicationPublished {
		s.publicationMu.Unlock()
		return
	}
	s.publication = event
	close(s.publicationChanged)
	s.publicationChanged = make(chan struct{})
	s.events.publish(event)
	s.publicationMu.Unlock()
}

func (s *Service) resetPublication() {
	s.d.mu.Lock()
	delete(s.d.descriptors, s.id)
	s.d.mu.Unlock()
	s.handlePublication(PublicationEvent{State: PublicationPending})
}

// SubscribeCloser registers c for closure with the service. The returned
// function removes the registration without closing c.
func (s *Service) SubscribeCloser(c io.Closer) (func(), error) {
	resource, err := s.scope.add(c)
	if err != nil {
		return nil, err
	}
	return func() {
		s.scope.mu.Lock()
		delete(s.scope.items, resource)
		s.scope.mu.Unlock()
	}, nil
}

// Drain withdraws the service, closes its listeners, and waits for accepted
// connections to close. If ctx ends, Drain closes the remaining connections.
func (s *Service) Drain(ctx context.Context) error {
	s.once.Do(func() { s.err = s.close(ctx, true) })
	return s.err
}

func (s *Service) Close() error {
	s.once.Do(func() { s.err = s.close(context.Background(), false) })
	return s.err
}

func (s *Service) close(ctx context.Context, drain bool) error {
	s.mu.Lock()
	s.closing = true
	close(s.closingCh)
	s.acceptedMu.Lock()
	s.stopping = true
	s.signalAcceptedLocked()
	s.acceptedMu.Unlock()

	s.d.mu.Lock()
	driverClosing := s.d.closed
	s.d.mu.Unlock()
	var result error
	if s.active && !driverClosing {
		_, result = s.d.command(context.Background(), "DEL_ONION "+s.id)
		if result != nil {
			_ = s.d.Close()
		}
	}
	s.active = false
	for _, binding := range s.ports {
		if binding.resource != nil {
			result = errors.Join(result, binding.resource.Close())
			binding.listener = nil
			binding.resource = nil
			binding.claimed = false
			binding.generation++
		}
	}
	s.mu.Unlock()

	if drain && result == nil {
		if waitErr := s.waitAccepted(ctx); waitErr != nil {
			result = errors.Join(result, waitErr)
		}
	}
	result = errors.Join(result, s.registration.Close())
	s.d.mu.Lock()
	delete(s.d.services, s)
	delete(s.d.descriptors, s.id)
	delete(s.d.keyNames, s.keyName)
	s.d.mu.Unlock()
	clear(s.key.expanded[:])
	return result
}

func (s *Service) waitAccepted(ctx context.Context) error {
	for {
		s.acceptedMu.Lock()
		if len(s.accepted) == 0 && s.accepting == 0 {
			s.acceptedMu.Unlock()
			return nil
		}
		changed := s.acceptedChanged
		s.acceptedMu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-changed:
		}
	}
}

func (s *Service) signalAcceptedLocked() {
	close(s.acceptedChanged)
	s.acceptedChanged = make(chan struct{})
}

type onionAddr string

func (a onionAddr) Network() string { return "tcp" }
func (a onionAddr) String() string  { return string(a) }

type serviceListener struct {
	s          *Service
	port       uint16
	generation uint64
	listener   net.Listener
	address    onionAddr
	mu         sync.Mutex
	closed     bool
}

func (l *serviceListener) Addr() net.Addr { return l.address }
func (l *serviceListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	err := l.s.removePort(context.Background(), l.port, l.generation)
	if err == nil {
		l.closed = true
	}
	return err
}
func (l *serviceListener) Accept() (net.Conn, error) {
	l.s.acceptedMu.Lock()
	if l.s.stopping {
		l.s.acceptedMu.Unlock()
		return nil, ErrClosed
	}
	l.s.accepting++
	l.s.signalAcceptedLocked()
	l.s.acceptedMu.Unlock()

	conn, err := l.listener.Accept()
	l.s.acceptedMu.Lock()
	l.s.accepting--
	l.s.signalAcceptedLocked()
	l.s.acceptedMu.Unlock()
	if err != nil {
		return nil, err
	}
	return l.s.trackAccepted(conn)
}
func (l *serviceListener) AcceptTCP() (gonnect.TCPConn, error) {
	conn, err := l.Accept()
	if err != nil {
		return nil, err
	}
	return &tcpView{Conn: conn}, nil
}
func (l *serviceListener) SetDeadline(deadline time.Time) error {
	if listener, ok := l.listener.(interface{ SetDeadline(time.Time) error }); ok {
		return listener.SetDeadline(deadline)
	}
	return ErrUnsupported
}

var _ gonnect.TCPListener = (*serviceListener)(nil)

type serviceConn struct {
	net.Conn
	s        *Service
	resource *resource
	once     sync.Once
	err      error
}

func (s *Service) trackAccepted(conn net.Conn) (net.Conn, error) {
	tracked := &serviceConn{Conn: conn, s: s}
	s.acceptedMu.Lock()
	if s.stopping {
		s.acceptedMu.Unlock()
		_ = conn.Close()
		return nil, ErrClosed
	}
	s.accepted[tracked] = struct{}{}
	s.signalAcceptedLocked()
	s.acceptedMu.Unlock()
	resource, err := s.scope.add(closerFunc(tracked.closeRaw))
	if err != nil {
		_ = tracked.closeRaw()
		return nil, err
	}
	tracked.resource = resource
	return tracked, nil
}

func (c *serviceConn) Close() error {
	c.once.Do(func() { c.err = c.resource.Close() })
	return c.err
}

func (c *serviceConn) closeRaw() error {
	err := c.Conn.Close()
	c.s.acceptedMu.Lock()
	delete(c.s.accepted, c)
	c.s.signalAcceptedLocked()
	c.s.acceptedMu.Unlock()
	return err
}
