package tordriver

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
)

// Tor forbids external SOCKS transport plugins with Socks5Proxy. Give each
// Go bridge a logical destination on the authenticated proxy instead. Retired
// destinations must never reach the outbound network, even after a rollback.
var routeIPv4 = netip.MustParsePrefix("127.128.0.0/9")
var routeIPv6 = netip.MustParsePrefix("fd00:746f:7200::/104")

func isTransportRoute(addr netip.Addr) bool {
	return routeIPv4.Contains(addr.Unmap()) || routeIPv6.Contains(addr)
}

func (d *Driver) prepareRoutes(ctx context.Context, bridges, old []Bridge) error {
	routes := make(map[[sha256.Size]byte]string)
	for _, b := range old {
		if b.route != "" {
			routes[bridgeRouteKey(b)] = b.route
		}
	}
	assignments := &d.assignments
	next := assignments.next
	var additions []byte
	for i, b := range bridges {
		ap, _ := netip.ParseAddrPort(b.Address)
		if d.methods[b.Transport].Dial == nil {
			if d.gate.reserveRoutes && isTransportRoute(ap.Addr()) {
				return fmt.Errorf("tor-driver: bridge address in reserved transport range")
			}
			continue
		}
		key := bridgeRouteKey(b)
		if route, ok := routes[key]; ok {
			bridges[i].route = route
			continue
		}
		id, restored := assignments.reusable[key]
		if !restored {
			if next >= maxTransportRoutes {
				return errors.New("tor-driver: transport address space exhausted")
			}
			id = next
			next++
			if assignments.files != nil {
				additions = append(additions, key[:]...)
			}
		}
		alias := netip.AddrFrom4([4]byte{127, 128 | byte(id>>16), byte(id >> 8), byte(id)})
		if ap.Addr().Is6() {
			v := routeIPv6.Addr().As16()
			v[13], v[14], v[15] = byte(id>>16), byte(id>>8), byte(id)
			alias = netip.AddrFrom16(v)
		}
		bridges[i].route = netip.AddrPortFrom(alias, ap.Port()).String()
		routes[key] = bridges[i].route
	}
	if len(additions) > 0 {
		if err := assignments.save(ctx, additions); err != nil {
			return err
		}
	}
	for key := range routes {
		delete(assignments.reusable, key)
	}
	assignments.next = next
	return nil
}

type bridgeRoute struct {
	bridge Bridge
	dial   TransportDial
}

func (d *Driver) activateBridges(bridges []Bridge) {
	routes := make(map[string]bridgeRoute)
	for _, b := range bridges {
		if b.route != "" {
			routes[b.route] = bridgeRoute{b, d.methods[b.Transport].Dial}
		}
	}
	d.gate.mu.Lock()
	d.gate.routes = routes
	d.gate.mu.Unlock()
	d.setActiveTransports(managedTransports(bridges, d.cfg.Transports))
}

// All lower-level streams belong to this handshake and its resulting session.
// This also closes partial handshakes that return an error or a late stream.
func (r bridgeRoute) connect(ctx context.Context, g *outboundGate, e *epoch) (net.Conn, error) {
	session := newScope()
	lifetime, err := e.add(session)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = session.Close() })
	dial := func(callCtx context.Context, network, address string) (net.Conn, error) {
		callCtx, finish := session.operation(callCtx)
		defer finish()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		c, err := g.dialOutbound(callCtx, e, network, address)
		if err != nil {
			return nil, err
		}
		tracked, err := session.track(c)
		if err != nil {
			return nil, err
		}
		return tracked, nil
	}
	c, err := r.dial(ctx, r.bridge.Address, maps.Clone(r.bridge.Args), dial)
	if !stop() || ctx.Err() != nil || err != nil || c == nil {
		if c != nil {
			_ = c.Close()
		}
		_ = lifetime.Close()
		return nil, errors.Join(ErrOutboundUnavailable, err, ctx.Err())
	}
	return &proxyPair{Conn: c, inc: lifetime}, nil
}
