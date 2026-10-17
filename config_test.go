package tordriver

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/asciimoth/gobox"
)

func configDeps() Dependencies {
	return Dependencies{Sandboxes: &fixtureSandboxes{}, Clock: testClock{}, Random: rand.Reader, Logger: NopLogger{}}
}
func TestConfigWhitelistAndBridgeFallback(t *testing.T) {
	cfg := Config{UseBridges: true, Bridges: []Bridge{{Transport: "snowflake", Address: "ignored"}}}
	if _, err := validate(cfg, configDeps()); err == nil {
		t.Fatal("empty bridge mode fell back to public guards")
	}
	cfg.Bridges = append(cfg.Bridges, Bridge{Address: "192.0.2.1:443"})
	v, err := validate(cfg, configDeps())
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Bridges) != 1 {
		t.Fatal("unsupported bridge retained")
	}
	cfg.Transports = []TransportConfig{{Kind: "snowflake", Program: "snowflake"}}
	if _, err = validate(cfg, configDeps()); !errors.Is(err, ErrUnsupportedTransport) {
		t.Fatal(err)
	}
	cfg.Transports = nil
	cfg.Bridges = []Bridge{{Address: "bridge.example:443"}}
	if _, err = validate(cfg, configDeps()); err == nil {
		t.Fatal("bridge hostname could cause OS DNS")
	}
}
func TestRenderedConfigPinsProxyAndOwnsDefaults(t *testing.T) {
	cfg, err := validate(Config{}, configDeps())
	if err != nil {
		t.Fatal(err)
	}
	s := renderConfig(cfg, "/tmp/state", "/tmp/control-port", "/tmp/control-cookie", "127.0.0.1:1234", "user", "password", 1, nil)
	for _, line := range []string{"Socks5Proxy 127.0.0.1:1234\n", "DisableNetwork 1\n", "CookieAuthentication 1\n", "ClientOnly 1\n", "NoExec 1\n", "SafeLogging 1\n", "Sandbox 0\n"} {
		if !strings.Contains(s, line) {
			t.Fatal("missing", line)
		}
	}
	if strings.Contains(s, "%include") {
		t.Fatal("external config included")
	}
}
func TestTypedObfs4Validation(t *testing.T) {
	program := gobox.ProgramID("obfs4")
	cfg := Config{UseBridges: true, Transports: []TransportConfig{{Kind: Obfs4, Program: program}}, Bridges: []Bridge{{Transport: Obfs4, Address: "[2001:db8::1]:443", Fingerprint: Fingerprint(strings.Repeat("A", 40)), Obfs4Certificate: base64.RawStdEncoding.EncodeToString(make([]byte, 52))}}}
	if _, err := validate(cfg, configDeps()); err != nil {
		t.Fatal(err)
	}
	rendered := renderConfig(cfg, "/tmp/state", "/tmp/control-port", "/tmp/control-cookie", "127.0.0.1:1234", "user", "password", 1, map[gobox.ProgramID]string{program: "/program/obfs4"})
	if !strings.Contains(rendered, "ClientTransportPlugin obfs4 exec \"/program/obfs4\"\n") {
		t.Fatal("transport program was not rendered as a Tor exec token")
	}
	cfg.Transports[0].Program = "program with-space"
	if _, err := validate(cfg, configDeps()); err == nil {
		t.Fatal("ambiguous transport executable accepted")
	}
	cfg.Transports[0].Program = program
	cfg.Bridges[0].Obfs4Certificate += "\nSocks5Proxy evil"
	if _, err := validate(cfg, configDeps()); err == nil {
		t.Fatal("bridge option injection accepted")
	}
	cfg = Config{TorProgram: "tor\ninvalid"}
	if _, err := validate(cfg, configDeps()); err == nil {
		t.Fatal("program injection accepted")
	}
	cfg = Config{Transports: []TransportConfig{{Kind: Obfs4, Program: program}}}
	if _, err := validate(cfg, configDeps()); err != nil {
		t.Fatalf("standby transport rejected: %v", err)
	}
}

func TestBroaderTypedClientConfiguration(t *testing.T) {
	fp := Fingerprint(strings.Repeat("1", 40))
	cfg, err := validate(Config{
		ConnectionPadding:  ReducedConnectionPadding,
		CircuitPadding:     ReducedCircuitPadding,
		ReachableORPorts:   []uint16{80, 443},
		MaxPendingCircuits: 12,
		NumCPUs:            2,
		ClientIP:           ClientPreferIPv6,
		OnionTraffic:       RejectOnionTraffic,
		ExcludeExitNodes:   []Fingerprint{fp},
	}, configDeps())
	if err != nil {
		t.Fatal(err)
	}
	rendered := renderConfig(cfg, "/tmp/state", "/tmp/control-port", "/tmp/control-cookie", "127.0.0.1:1234", "user", "password", 1, nil)
	for _, line := range []string{
		"ConnectionPadding auto\n", "ReducedConnectionPadding 1\n",
		"CircuitPadding 1\n", "ReducedCircuitPadding 1\n",
		"ReachableORAddresses *:80,*:443\n", "MaxClientCircuitsPending 12\n", "NumCPUs 2\n",
		"ClientUseIPv4 1\n", "ClientUseIPv6 1\n", "ClientPreferIPv6ORPort 1\n",
		"SocksPort 127.0.0.1:auto IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth IPv6Traffic PreferIPv6 NoOnionTraffic\n",
		"ExcludeExitNodes $" + strings.Repeat("1", 40) + "\n",
	} {
		if !strings.Contains(rendered, line) {
			t.Errorf("rendered configuration is missing %q", line)
		}
	}

	invalid := Config{ReachableORPorts: []uint16{443, 443}}
	if _, err = validate(invalid, configDeps()); err == nil {
		t.Fatal("duplicate relay port accepted")
	}
	invalid = Config{ClientIP: ClientIPv6Only, ClientIPv6: true}
	if _, err = validate(invalid, configDeps()); err == nil {
		t.Fatal("conflicting IPv6 settings accepted")
	}
	invalid = Config{OnionTraffic: 99}
	if _, err = validate(invalid, configDeps()); err == nil {
		t.Fatal("invalid onion traffic policy accepted")
	}
	invalid = Config{MaxPendingCircuits: 1025}
	if _, err = validate(invalid, configDeps()); err == nil {
		t.Fatal("invalid pending circuit limit accepted")
	}
}
