package tordriver

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/asciimoth/gonnect"
	"github.com/asciimoth/socksgo"
)

// Use a private alias: callers cannot obtain or mutate the SOCKS client.
// Unimplemented gonnect operations inherit fail-closed behavior.
type rejected = gonnect.RejectNetwork

// Network is a closable Tor client network. Dial and Tor DNS resolution work;
// listening, UDP, multicast and unsupported DNS record types are rejected.
type Network struct {
	rejected
	d            *Driver
	cfg          NetworkConfig
	id           string
	scope        *scope
	registration *resource
}

var _ gonnect.Network = (*Network)(nil)

func (d *Driver) NewNetwork(cfg NetworkConfig) (*Network, error) {
	const knownIsolation = IsolateDestinationAddress | IsolateDestinationPort
	if cfg.Circuits > IsolateEachConnection || cfg.Isolation&^knownIsolation != 0 {
		return nil, fmt.Errorf("tor-driver: invalid circuit policy")
	}
	id, err := d.token()
	if err != nil {
		return nil, err
	}
	n := &Network{d: d, cfg: cfg, id: id, scope: newScope()}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		_ = n.scope.Close()
		return nil, ErrClosed
	}
	n.registration, err = d.resources.add(n.scope)
	if err != nil {
		return nil, err
	}
	d.networks[n] = struct{}{}
	return n, nil
}
func (n *Network) Close() error {
	err := n.registration.Close()
	n.d.mu.Lock()
	delete(n.d.networks, n)
	n.d.mu.Unlock()
	return err
}
func (n *Network) SubscribeCloser(c io.Closer) (func(), error) {
	r, err := n.scope.add(c)
	if err != nil {
		return nil, err
	}
	return func() { n.scope.mu.Lock(); delete(n.scope.items, r); n.scope.mu.Unlock() }, nil
}

var _ gonnect.CloserSubscriber = (*Network)(nil)

type socksOperation struct {
	mu            sync.Mutex
	ended         bool
	ctx           context.Context
	client        *socksgo.Client
	stops         []func() bool
	connections   []net.Conn
	finishContext func()
}

func (n *Network) operation(ctx context.Context, address, port string) (*socksOperation, error) {
	if n.scope.ctx.Err() != nil {
		return nil, ErrClosed
	}
	ctx, finish := n.scope.operation(ctx)
	ctx, cancel := n.d.deps.Clock.Timeout(ctx, n.d.cfg.DialTimeout)
	o := &socksOperation{ctx: ctx, finishContext: func() { cancel(); finish() }}
	endpoint := n.d.socksEndpoint()
	id := n.id
	if n.cfg.Circuits == IsolateEachConnection {
		var err error
		id, err = n.d.token()
		if err != nil {
			o.finishContext()
			return nil, err
		}
	} else if n.cfg.Isolation != 0 {
		h := sha256.New()
		_, _ = io.WriteString(h, id)
		if n.cfg.Isolation&IsolateDestinationAddress != 0 {
			_, _ = io.WriteString(h, "\x00address\x00"+strings.ToLower(address))
		}
		if n.cfg.Isolation&IsolateDestinationPort != 0 {
			_, _ = io.WriteString(h, "\x00port\x00"+port)
		}
		id = fmt.Sprintf("%x", h.Sum(nil))
	}
	c := &socksgo.Client{
		SocksVersion: "5", ProxyNet: "tcp", ProxyAddr: endpoint, TorLookup: true,
		// socksgo otherwise bypasses SOCKS for loopback targets.
		Filter:   func(string, string) bool { return false },
		Resolver: &gonnect.RejectNetwork{},
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != endpoint || !tcpNetwork(network) {
				return nil, ErrUnsupported
			}
			raw, err := n.d.deps.LocalNetwork.Dial(ctx, network, address)
			if err != nil {
				if raw != nil {
					_ = raw.Close()
				}
				return nil, err
			}
			if raw == nil {
				return nil, fmt.Errorf("tor-driver: local dial returned nil connection")
			}
			conn, err := n.scope.track(raw)
			if err != nil {
				return nil, err
			}
			o.mu.Lock()
			if o.ended {
				o.mu.Unlock()
				_ = conn.Close()
				return nil, ErrClosed
			}
			o.connections = append(o.connections, conn)
			o.stops = append(o.stops, context.AfterFunc(o.ctx, func() { _ = conn.Close() }))
			o.mu.Unlock()
			return conn, nil
		},
	}
	o.client = c.WithTorIsolation(&id)
	return o, nil
}
func (o *socksOperation) end(success bool) {
	o.mu.Lock()
	o.ended = true
	stops := o.stops
	connections := o.connections
	o.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
	if !success {
		for _, conn := range connections {
			_ = conn.Close()
		}
	}
	o.finishContext()
}
func tcpNetwork(n string) bool { return n == "tcp" || n == "tcp4" || n == "tcp6" }

func (n *Network) Dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if !tcpNetwork(network) {
		return nil, ErrUnsupported
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || !safeText(address) {
		return nil, fmt.Errorf("tor-driver: invalid target")
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if (network == "tcp4" && !ip.Unmap().Is4()) || (network == "tcp6" && !ip.Is6()) {
			return nil, fmt.Errorf("tor-driver: address family mismatch")
		}
	}
	o, err := n.operation(ctx, host, port)
	if err != nil {
		return nil, err
	}
	defer func() { o.end(err == nil) }()
	conn, err = o.client.Dial(o.ctx, network, address)
	if err == nil {
		err = o.ctx.Err()
	}
	if err == nil && conn == nil {
		err = fmt.Errorf("tor-driver: SOCKS returned nil connection")
	}
	if err == nil {
		err = conn.SetDeadline(time.Time{})
	}
	if err != nil && conn != nil {
		_ = conn.Close()
		conn = nil
	}
	return conn, err
}
func (n *Network) DialTCP(ctx context.Context, network, laddr, raddr string) (gonnect.TCPConn, error) {
	if laddr != "" {
		return nil, ErrUnsupported
	}
	c, err := n.Dial(ctx, network, raddr)
	if err != nil {
		return nil, err
	}
	return &tcpView{Conn: c}, nil
}
func (n *Network) LookupIP(ctx context.Context, network, host string) (ips []net.IP, err error) {
	if network != "ip" && network != "ip4" && network != "ip6" {
		return nil, ErrUnsupported
	}
	if strings.HasSuffix(strings.ToLower(host), ".onion") {
		return nil, fmt.Errorf("tor-driver: onion names have no DNS address; Dial the name directly")
	}
	o, err := n.operation(ctx, host, "")
	if err != nil {
		return nil, err
	}
	defer func() { o.end(false) }()
	ips, err = o.client.LookupIP(o.ctx, network, host)
	if err == nil {
		err = o.ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	filtered := ips[:0]
	for _, ip := range ips {
		if network == "ip" || (network == "ip4" && ip.To4() != nil) || (network == "ip6" && ip.To4() == nil) {
			filtered = append(filtered, ip)
		}
	}
	if len(filtered) == 0 {
		return nil, &net.DNSError{Err: "no matching address", Name: host, IsNotFound: true}
	}
	return filtered, nil
}
func (n *Network) LookupAddr(ctx context.Context, address string) (names []string, err error) {
	if _, err = netip.ParseAddr(address); err != nil {
		return nil, err
	}
	o, err := n.operation(ctx, address, "")
	if err != nil {
		return nil, err
	}
	defer o.end(false)
	names, err = o.client.LookupAddr(o.ctx, address)
	if err == nil {
		err = o.ctx.Err()
	}
	return names, err
}
func (n *Network) LookupHost(ctx context.Context, host string) ([]string, error) {
	ips, err := n.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}
func (n *Network) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	ips, err := n.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	result := make([]net.IPAddr, len(ips))
	for i, ip := range ips {
		result[i] = net.IPAddr{IP: ip}
	}
	return result, nil
}
func (n *Network) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	ips, err := n.LookupIP(ctx, network, host)
	if err != nil {
		return nil, err
	}
	result := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip); ok {
			result = append(result, a.Unmap())
		}
	}
	return result, nil
}
func (n *Network) LookupPort(ctx context.Context, network, service string) (int, error) {
	if n.scope.ctx.Err() != nil {
		return 0, ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return gonnect.LookupPortOffline(network, service)
}
