package tordriver

import (
	"bytes"
	"encoding/base64"
	"net"
	"path/filepath"
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
	binary, err := filepath.Abs("tor")
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, kind byte, address, fingerprint, certificate string, iat byte) {
		if len(address)+len(fingerprint)+len(certificate) > 4096 {
			t.Skip()
		}
		transport := Plain
		var registrations []TransportConfig
		switch kind % 3 {
		case 1:
			transport = Obfs4
			registrations = []TransportConfig{{Kind: Obfs4, Executable: binary}}
		case 2:
			transport = Transport("unsupported")
		}
		cfg := Config{
			TorExecutable: binary, UseBridges: true, Transports: registrations,
			Bridges: []Bridge{{Transport: transport, Address: address, Fingerprint: Fingerprint(fingerprint), Obfs4Certificate: certificate, IAT: IATMode(iat)}},
		}
		validated, validateErr := validate(cfg, configDeps())
		if validateErr == nil {
			_ = renderConfig(validated, filepath.Dir(binary), filepath.Dir(binary), "127.0.0.1:1", "u", "p", 1)
		}
	})
}
