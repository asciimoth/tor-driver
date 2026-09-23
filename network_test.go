package tordriver

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type socksRecord struct {
	user, password, target string
	atyp                   byte
}

func fakeSOCKS(t *testing.T, records chan<- socksRecord) *dialNetwork {
	t.Helper()
	return &dialNetwork{dial: func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "127.0.0.1:19050" {
			return nil, fmt.Errorf("direct target escaped local SOCKS dialer")
		}
		a, b := net.Pipe()
		go func() {
			defer func() { _ = b.Close() }()
			_ = b.SetDeadline(time.Now().Add(5 * time.Second))
			var h [2]byte
			if _, e := io.ReadFull(b, h[:]); e != nil {
				return
			}
			methods := make([]byte, int(h[1]))
			if _, e := io.ReadFull(b, methods); e != nil {
				return
			}
			if _, e := b.Write([]byte{5, 2}); e != nil {
				return
			}
			if _, e := io.ReadFull(b, h[:]); e != nil {
				return
			}
			user := make([]byte, int(h[1]))
			if _, e := io.ReadFull(b, user); e != nil {
				return
			}
			var length [1]byte
			if _, e := io.ReadFull(b, length[:]); e != nil {
				return
			}
			password := make([]byte, int(length[0]))
			if _, e := io.ReadFull(b, password); e != nil {
				return
			}
			if _, e := b.Write([]byte{1, 0}); e != nil {
				return
			}
			var hdr [4]byte
			if _, e := io.ReadFull(b, hdr[:]); e != nil {
				return
			}
			var host string
			switch hdr[3] {
			case 3:
				if _, e := io.ReadFull(b, length[:]); e != nil {
					return
				}
				buf := make([]byte, int(length[0]))
				if _, e := io.ReadFull(b, buf); e != nil {
					return
				}
				host = string(buf)
			case 1:
				var ip [4]byte
				if _, e := io.ReadFull(b, ip[:]); e != nil {
					return
				}
				host = net.IP(ip[:]).String()
			case 4:
				var ip [16]byte
				if _, e := io.ReadFull(b, ip[:]); e != nil {
					return
				}
				host = net.IP(ip[:]).String()
			default:
				return
			}
			var port [2]byte
			if _, e := io.ReadFull(b, port[:]); e != nil {
				return
			}
			records <- socksRecord{string(user), string(password), net.JoinHostPort(host, fmt.Sprint(binary.BigEndian.Uint16(port[:]))), hdr[3]}
			if _, e := b.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); e != nil {
				return
			}
			_, _ = io.Copy(b, b)
		}()
		return a, nil
	}}
}
func TestIsolationAndNoLoopbackBypass(t *testing.T) {
	records := make(chan socksRecord, 10)
	d := testDriver(fakeSOCKS(t, records))
	defer func() { _ = d.Close() }()
	a, _ := d.NewNetwork(NetworkConfig{})
	b, _ := d.NewNetwork(NetworkConfig{})
	fresh, _ := d.NewNetwork(NetworkConfig{Circuits: IsolateEachConnection})
	dial := func(n *Network, target string) socksRecord {
		t.Helper()
		c, err := n.Dial(context.Background(), "tcp", target)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
		return <-records
	}
	r1 := dial(a, "unresolved.example:80")
	r2 := dial(a, "127.0.0.1:80")
	r3 := dial(b, "unresolved.example:80")
	if r1.password != r2.password || r1.password == r3.password {
		t.Fatal("session isolation mismatch")
	}
	if r1.atyp != 3 || r1.target != "unresolved.example:80" {
		t.Fatal("hostname was not sent through SOCKS")
	}
	if r2.target != "127.0.0.1:80" {
		t.Fatal("loopback bypass")
	}
	r4 := dial(fresh, "unresolved.example:80")
	r5 := dial(fresh, "unresolved.example:80")
	if r4.password == r5.password {
		t.Fatal("per-connection credentials reused")
	}
	if _, err := a.Dial(context.Background(), "udp", "1.1.1.1:53"); err == nil {
		t.Fatal("UDP accepted")
	}
	if a.IsNative() {
		t.Fatal("Tor network must not advertise native bypass")
	}
}
func TestNetworkCloseClosesLiveConnection(t *testing.T) {
	records := make(chan socksRecord, 2)
	d := testDriver(fakeSOCKS(t, records))
	defer func() { _ = d.Close() }()
	n, _ := d.NewNetwork(NetworkConfig{})
	c, err := n.Dial(context.Background(), "tcp", "unresolved.example:80")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = n.Close()
	assertClosed(t, c)
	if _, err = n.Dial(context.Background(), "tcp", "unresolved.example:80"); err == nil {
		t.Fatal("closed network accepted dial")
	}
	if _, err = d.NewNetwork(NetworkConfig{Circuits: 99}); err == nil {
		t.Fatal("invalid enum accepted")
	}
}
func TestNetworkCloseCancelsHandshake(t *testing.T) {
	accepted := make(chan net.Conn, 1)
	d := testDriver(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		a, b := net.Pipe()
		accepted <- b
		return a, nil
	}})
	defer func() { _ = d.Close() }()
	n, _ := d.NewNetwork(NetworkConfig{})
	result := make(chan error, 1)
	go func() { _, err := n.Dial(context.Background(), "tcp", "never.example:80"); result <- err }()
	b := <-accepted
	defer func() { _ = b.Close() }()
	_ = n.Close()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("handshake succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake not canceled")
	}
}
func TestConcurrentNetworkCreateClose(t *testing.T) {
	d := testDriver(&dialNetwork{})
	defer func() { _ = d.Close() }()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := d.NewNetwork(NetworkConfig{})
			if err == nil {
				_ = n.Close()
			}
		}()
	}
	_ = d.Close()
	wg.Wait()
}
