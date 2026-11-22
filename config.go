package tordriver

import (
	"encoding/hex"
	"fmt"
	"maps"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/asciimoth/gobox"
)

const (
	// DefaultSandboxSlot is the owner-local slot used when Config omits one.
	DefaultSandboxSlot = "tor"
	// DefaultSandboxTemplate is the sandbox template used when Config omits one.
	DefaultSandboxTemplate gobox.TemplateID = "tor"
	// DefaultTorProgram is the Tor program used when Config omits one.
	DefaultTorProgram gobox.ProgramID = "tor"
)

func validate(cfg Config, deps Dependencies) (Config, error) {
	if deps.Sandboxes == nil || deps.Clock == nil || deps.Random == nil || deps.Logger == nil {
		return cfg, fmt.Errorf("tor-driver: all dependencies except Outbound are required")
	}
	if cfg.SandboxSlot == "" {
		cfg.SandboxSlot = DefaultSandboxSlot
	}
	if cfg.SandboxTemplate == "" {
		cfg.SandboxTemplate = DefaultSandboxTemplate
	}
	if cfg.TorProgram == "" {
		cfg.TorProgram = DefaultTorProgram
	}
	if err := gobox.ValidateName(cfg.SandboxSlot); err != nil {
		return cfg, fmt.Errorf("tor-driver: invalid sandbox slot: %w", err)
	}
	if err := gobox.ValidateName(string(cfg.SandboxTemplate)); err != nil {
		return cfg, fmt.Errorf("tor-driver: invalid sandbox template: %w", err)
	}
	if err := gobox.ValidateName(string(cfg.TorProgram)); err != nil {
		return cfg, fmt.Errorf("tor-driver: invalid Tor program: %w", err)
	}
	if cfg.StateDirectory.Rel != "" {
		if err := gobox.ValidatePath(cfg.StateDirectory, false); err != nil {
			return cfg, fmt.Errorf("tor-driver: invalid state directory: %w", err)
		}
	}
	if cfg.Sandbox > LinuxSandbox || cfg.LogLevel > LogError ||
		cfg.ConnectionPadding > DisableConnectionPadding || cfg.CircuitPadding > DisableCircuitPadding ||
		cfg.ClientIP > ClientIPv6Only || cfg.OnionTraffic > RejectOnionTraffic {
		return cfg, fmt.Errorf("tor-driver: invalid enum")
	}
	if cfg.ClientIPv6 && cfg.ClientIP != ClientIPv4Only && cfg.ClientIP != ClientDualStack {
		return cfg, fmt.Errorf("tor-driver: ClientIPv6 conflicts with ClientIP")
	}
	if cfg.ClientIPv6 {
		cfg.ClientIP = ClientDualStack
	}
	if cfg.OutboundFailures > LatchOutboundErrors {
		return cfg, fmt.Errorf("tor-driver: invalid outbound failure policy")
	}
	defaults := []struct {
		p *time.Duration
		d time.Duration
	}{
		{&cfg.StartupTimeout, 30 * time.Second}, {&cfg.CommandTimeout, 10 * time.Second},
		{&cfg.DialTimeout, 90 * time.Second}, {&cfg.ShutdownTimeout, 10 * time.Second},
		{&cfg.MaxCircuitDirtiness, 10 * time.Minute},
	}
	for _, d := range defaults {
		if *d.p == 0 {
			*d.p = d.d
		}
		if *d.p < time.Second || *d.p > 24*time.Hour {
			return cfg, fmt.Errorf("tor-driver: timeout out of range")
		}
	}
	if cfg.CircuitBuildTimeout < 0 || (cfg.CircuitBuildTimeout > 0 && cfg.CircuitBuildTimeout < time.Second) || cfg.CircuitBuildTimeout > 24*time.Hour {
		return cfg, fmt.Errorf("tor-driver: invalid circuit build timeout")
	}
	if cfg.MaxProxyConnections == 0 {
		cfg.MaxProxyConnections = 256
	}
	if cfg.MaxProxyConnections < 1 || cfg.MaxProxyConnections > 65536 {
		return cfg, fmt.Errorf("tor-driver: invalid proxy connection limit")
	}
	if cfg.MaxPendingCircuits > 1024 {
		return cfg, fmt.Errorf("tor-driver: pending circuit limit exceeds Tor maximum")
	}
	if (cfg.BandwidthRate == 0) != (cfg.BandwidthBurst == 0) || cfg.BandwidthBurst < cfg.BandwidthRate {
		return cfg, fmt.Errorf("tor-driver: bandwidth rate/burst must be supplied together and burst >= rate")
	}
	for _, list := range [][]Fingerprint{cfg.EntryNodes, cfg.ExitNodes, cfg.ExcludeNodes, cfg.ExcludeExitNodes} {
		for _, fp := range list {
			if !validFingerprint(fp) {
				return cfg, fmt.Errorf("tor-driver: invalid relay fingerprint")
			}
		}
	}
	cfg.EntryNodes = append([]Fingerprint(nil), cfg.EntryNodes...)
	cfg.ExitNodes = append([]Fingerprint(nil), cfg.ExitNodes...)
	cfg.ExcludeNodes = append([]Fingerprint(nil), cfg.ExcludeNodes...)
	cfg.ExcludeExitNodes = append([]Fingerprint(nil), cfg.ExcludeExitNodes...)
	cfg.ReachableORPorts = append([]uint16(nil), cfg.ReachableORPorts...)
	seenPorts := make(map[uint16]struct{}, len(cfg.ReachableORPorts))
	for _, port := range cfg.ReachableORPorts {
		if port == 0 {
			return cfg, fmt.Errorf("tor-driver: reachable relay port must be nonzero")
		}
		if _, exists := seenPorts[port]; exists {
			return cfg, fmt.Errorf("tor-driver: duplicate reachable relay port")
		}
		seenPorts[port] = struct{}{}
	}
	cfg.Transports = slices.Clone(cfg.Transports)
	registered := make(map[Transport]TransportConfig)
	for _, t := range cfg.Transports {
		if !methodName.MatchString(string(t.Kind)) || (t.Program == "") == (t.Dial == nil) {
			return cfg, fmt.Errorf("tor-driver: invalid transport registration")
		}
		if _, ok := registered[t.Kind]; ok {
			return cfg, fmt.Errorf("tor-driver: duplicate transport registration")
		}
		if t.Program != "" && (gobox.ValidateName(string(t.Program)) != nil || cfg.Sandbox == LinuxSandbox) {
			return cfg, fmt.Errorf("tor-driver: invalid managed transport program or sandbox")
		}
		registered[t.Kind] = t
	}
	var err error
	cfg.Bridges, err = validateBridges(cfg.UseBridges, cfg.Bridges, registered)
	return cfg, err
}

var methodName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
var argName = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func validToken(s string) bool {
	return !strings.ContainsAny(s, "\"#\\") && strings.IndexFunc(s, func(r rune) bool { return r <= 32 || r > 126 }) == -1
}

func validateBridges(enabled bool, bridges []Bridge, methods map[Transport]TransportConfig) ([]Bridge, error) {
	if enabled != (len(bridges) > 0) {
		return nil, fmt.Errorf("tor-driver: UseBridges must match the bridge list")
	}
	result := slices.Clone(bridges)
	for i, b := range result {
		t, ok := methods[b.Transport]
		if b.Transport != Plain && !ok {
			return nil, fmt.Errorf("tor-driver: bridge %d: %w", i, ErrUnsupportedTransport)
		}
		ap, err := numericEndpoint(b.Address, false)
		if err != nil || (b.Fingerprint != "" && !validFingerprint(b.Fingerprint)) {
			return nil, fmt.Errorf("tor-driver: invalid bridge %d endpoint or fingerprint", i)
		}
		if b.Transport == Plain && len(b.Args) != 0 {
			return nil, fmt.Errorf("tor-driver: arguments on plain bridge %d", i)
		}
		encodedSize := -1 // exclude the separator after the final argument
		for k, v := range b.Args {
			encodedSize += len(k) + len(v) + strings.Count(v, ";") + 2
			if !argName.MatchString(k) || (t.Program != "" && !validToken(v)) {
				return nil, fmt.Errorf("tor-driver: invalid argument on bridge %d", i)
			}
		}
		if t.Program != "" && encodedSize > 510 {
			return nil, fmt.Errorf("tor-driver: bridge %d arguments exceed SOCKS5 capacity", i)
		}
		result[i].Address = ap.String()
		result[i].Args = maps.Clone(b.Args)
	}
	return result, nil
}
func safeText(s string) bool {
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func quote(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
func validFingerprint(f Fingerprint) bool {
	b, err := hex.DecodeString(string(f))
	return err == nil && len(b) == 20
}
func numericEndpoint(s string, loopback bool) (netip.AddrPort, error) {
	a, err := netip.ParseAddrPort(s)
	if err != nil || a.Port() == 0 || a.Addr().Zone() != "" || a.Addr().IsUnspecified() || (loopback && !a.Addr().IsLoopback()) {
		return netip.AddrPort{}, fmt.Errorf("tor-driver: invalid numeric endpoint")
	}
	return a, nil
}
func bit(v bool) int {
	if v {
		return 1
	}
	return 0
}
func fingerprints(v []Fingerprint) string {
	out := make([]string, len(v))
	for i, f := range v {
		out[i] = "$" + strings.ToUpper(string(f))
	}
	return strings.Join(out, ",")
}

func bridgeLines(bridges []Bridge) []string {
	lines := make([]string, 0, len(bridges))
	for _, br := range bridges {
		v := br.Address
		if br.route != "" {
			v = br.route
		} else if br.Transport != Plain {
			v = string(br.Transport) + " " + v
		}
		if br.Fingerprint != "" {
			v += " " + string(br.Fingerprint)
		}
		if br.route == "" {
			for _, k := range slices.Sorted(maps.Keys(br.Args)) {
				v += " " + k + "=" + br.Args[k]
			}
		}
		lines = append(lines, v)
	}
	return lines
}

func managedTransports(bridges []Bridge, registrations []TransportConfig) []TransportConfig {
	used := make(map[Transport]bool, len(bridges))
	for _, b := range bridges {
		used[b.Transport] = true
	}
	var active []TransportConfig
	for _, t := range registrations {
		if t.Program != "" && used[t.Kind] {
			active = append(active, t)
		}
	}
	return active
}

func (t TransportConfig) pluginLine(paths map[gobox.ProgramID]string) string {
	return string(t.Kind) + " exec " + paths[t.Program]
}

// With auto, Tor uses the address family from the Bridge line. A fixed IPv6
// preference can select an advertised ORPort that has no Go transport route.
func preferIPv6ORPort(policy ClientIPPolicy, useBridges bool) string {
	if !useBridges && (policy == ClientPreferIPv6 || policy == ClientIPv6Only) {
		return "1"
	}
	return "auto"
}

func socksPortOptions(c Config) string {
	options := []string{"127.0.0.1:auto", "IsolateSOCKSAuth", "KeepAliveIsolateSOCKSAuth", "IPv6Traffic"}
	if c.ClientIP == ClientPreferIPv6 || c.ClientIP == ClientIPv6Only {
		options = append(options, "PreferIPv6")
	}
	if c.ClientIP == ClientIPv6Only {
		options = append(options, "NoIPv4Traffic")
	}
	switch c.OnionTraffic {
	case OnionTrafficOnly:
		options = append(options, "OnionTrafficOnly")
	case RejectOnionTraffic:
		options = append(options, "NoOnionTraffic")
	}
	return strings.Join(options, " ")
}

func renderConfig(c Config, state, controlPort, controlCookie, proxy, user, password string, pid int, transportPaths map[gobox.ProgramID]string) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%s %s\n", k, v) }
	line("DataDirectory", quote(state))
	line("RunAsDaemon", "0")
	line("ControlPort", "127.0.0.1:auto")
	line("ControlPortWriteToFile", quote(controlPort))
	line("CookieAuthentication", "1")
	line("CookieAuthFile", quote(controlCookie))
	line("CookieAuthFileGroupReadable", "0")
	line("__OwningControllerProcess", strconv.Itoa(pid))
	line("DisableNetwork", "1")
	line("SocksPort", socksPortOptions(c))
	line("SocksPolicy", "accept 127.0.0.1")
	line("SocksPolicy", "reject *")
	line("Socks5Proxy", proxy)
	line("Socks5ProxyUsername", user)
	line("Socks5ProxyPassword", password)
	line("ClientOnly", "1")
	line("ORPort", "0")
	line("DirPort", "0")
	line("ExitRelay", "0")
	line("PublishServerDescriptor", "0")
	line("SafeLogging", "1")
	line("DisableDebuggerAttachment", "1")
	line("AvoidDiskWrites", "1")
	line("NoExec", strconv.Itoa(bit(len(transportPaths) == 0)))
	line("Sandbox", strconv.Itoa(bit(c.Sandbox == LinuxSandbox)))
	levels := []string{"notice", "warn", "err"}
	line("Log", levels[c.LogLevel]+" stdout")
	line("ConnectionPadding", []string{"auto", "1", "auto", "0"}[c.ConnectionPadding])
	line("ReducedConnectionPadding", strconv.Itoa(bit(c.ConnectionPadding == ReducedConnectionPadding)))
	line("CircuitPadding", strconv.Itoa(bit(c.CircuitPadding != DisableCircuitPadding)))
	line("ReducedCircuitPadding", strconv.Itoa(bit(c.CircuitPadding == ReducedCircuitPadding)))
	line("ClientUseIPv4", strconv.Itoa(bit(c.ClientIP != ClientIPv6Only)))
	line("ClientUseIPv6", strconv.Itoa(bit(c.ClientIP != ClientIPv4Only)))
	line("ClientPreferIPv6ORPort", preferIPv6ORPort(c.ClientIP, c.UseBridges))
	if len(c.ReachableORPorts) > 0 {
		ports := make([]string, len(c.ReachableORPorts))
		for i, port := range c.ReachableORPorts {
			ports[i] = "*:" + strconv.Itoa(int(port))
		}
		line("ReachableORAddresses", strings.Join(ports, ","))
	}
	if c.MaxPendingCircuits > 0 {
		line("MaxClientCircuitsPending", strconv.Itoa(int(c.MaxPendingCircuits)))
	}
	if c.NumCPUs > 0 {
		line("NumCPUs", strconv.Itoa(int(c.NumCPUs)))
	}
	line("MaxCircuitDirtiness", fmt.Sprintf("%d seconds", int64(c.MaxCircuitDirtiness/time.Second)))
	if c.CircuitBuildTimeout > 0 {
		line("CircuitBuildTimeout", fmt.Sprintf("%d seconds", int64(c.CircuitBuildTimeout/time.Second)))
	}
	if c.BandwidthRate > 0 {
		line("BandwidthRate", fmt.Sprintf("%d bytes", c.BandwidthRate))
		line("BandwidthBurst", fmt.Sprintf("%d bytes", c.BandwidthBurst))
	}
	if len(c.EntryNodes) > 0 {
		line("EntryNodes", fingerprints(c.EntryNodes))
	}
	if len(c.ExitNodes) > 0 {
		line("ExitNodes", fingerprints(c.ExitNodes))
	}
	if len(c.ExcludeNodes) > 0 {
		line("ExcludeNodes", fingerprints(c.ExcludeNodes))
	}
	if len(c.ExcludeExitNodes) > 0 {
		line("ExcludeExitNodes", fingerprints(c.ExcludeExitNodes))
	}
	line("StrictNodes", strconv.Itoa(bit(c.StrictNodes)))
	line("UseBridges", strconv.Itoa(bit(c.UseBridges)))
	for _, t := range managedTransports(c.Bridges, c.Transports) {
		line("ClientTransportPlugin", t.pluginLine(transportPaths))
	}
	for _, bridge := range bridgeLines(c.Bridges) {
		line("Bridge", bridge)
	}
	return b.String()
}
