package tordriver

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

type fuzzProxyConn struct {
	*bytes.Reader
	writes bytes.Buffer
}

func (c *fuzzProxyConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *fuzzProxyConn) Close() error                     { return nil }
func (c *fuzzProxyConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c *fuzzProxyConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c *fuzzProxyConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzProxyConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzProxyConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }

func FuzzProxyGreetingAuthAndConnect(f *testing.F) {
	valid := []byte{
		5, 1, 2,
		1, 1, 'u', 1, 'p',
		5, 1, 0, 1, 192, 0, 2, 1, 1, 187,
	}
	f.Add(valid)
	f.Add([]byte{5, 0})
	f.Add([]byte{4, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		p := &proxyServer{
			scope: newScope(), gate: &outboundGate{}, clock: testClock{},
			timeout: time.Second, user: []byte("u"), password: []byte("p"),
		}
		p.handle(&fuzzProxyConn{Reader: bytes.NewReader(data)})
		_ = p.scope.Close()
	})
}

func FuzzTypedBridgeValidation(f *testing.F) {
	cert := base64.RawStdEncoding.EncodeToString(make([]byte, 52))
	f.Add(byte(1), "192.0.2.1:443", strings.Repeat("A", 40), cert, byte(0))
	f.Add(byte(0), "[2001:db8::1]:9001", "", "", byte(0))
	f.Add(byte(2), "bridge.example:443", "short", "bad", byte(255))
	f.Add(byte(3), "192.0.2.1:443", "", "line one\nline two", byte(0))
	f.Fuzz(func(t *testing.T, kind byte, address, fingerprint, certificate string, iat byte) {
		if len(address)+len(fingerprint)+len(certificate) > 4096 {
			t.Skip()
		}
		bridge := Bridge{Address: address, Fingerprint: Fingerprint(fingerprint)}
		var registration TransportConfig
		switch kind % 4 {
		case 1:
			registration = TransportConfig{Kind: "obfs4", Program: "obfs4"}
		case 2:
			bridge.Transport = "unsupported"
		case 3:
			registration = TransportConfig{Kind: "sample", Dial: passthrough}
		}
		cfg := Config{UseBridges: true}
		if registration.Kind != Plain {
			bridge.Transport = registration.Kind
			bridge.Args = map[string]string{"cert": certificate, "iat-mode": strconv.Itoa(int(iat))}
			cfg.Transports = []TransportConfig{registration}
		}
		cfg.Bridges = []Bridge{bridge}
		validated, err := validate(cfg, configDeps())
		if err != nil {
			return
		}
		d := Driver{gate: &outboundGate{reserveRoutes: registration.Dial != nil}, methods: map[Transport]TransportConfig{registration.Kind: registration}}
		if err := d.prepareRoutes(context.Background(), validated.Bridges, nil); err != nil {
			t.Fatal(err)
		}
		line := bridgeLines(validated.Bridges)[0]
		if strings.ContainsAny(line, "\r\n") {
			t.Fatal("bridge rendered as multiple lines")
		}
		if registration.Dial != nil && strings.Contains(line, "cert=") {
			t.Fatal("Go transport arguments reached Tor")
		}
	})
}
