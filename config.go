package tordriver

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func validate(cfg Config, deps Dependencies) (Config, error) {
	if deps.FS == nil || deps.Processes == nil || deps.Clock == nil || deps.Random == nil || deps.Logger == nil || deps.LocalNetwork == nil {
		return cfg, fmt.Errorf("tor-driver: all dependencies except Outbound are required")
	}
	if !filepath.IsAbs(cfg.TorExecutable) || !safeText(cfg.TorExecutable) {
		return cfg, fmt.Errorf("tor-driver: TorExecutable must be an absolute path")
	}
	for _, p := range []string{cfg.TempRoot, cfg.StateDirectory} {
		if p != "" && (!filepath.IsAbs(p) || !safeText(p)) {
			return cfg, fmt.Errorf("tor-driver: directories must be absolute paths")
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
	if cfg.Sandbox == LinuxSandbox && deps.Processes.Platform() != "linux" {
		return cfg, ErrUnsupported
	}
	if cfg.Identity != nil {
		id := *cfg.Identity
		cfg.Identity = &id
		if id.UID == 0 || id.GID == 0 || deps.Processes.Platform() != "linux" {
			return cfg, fmt.Errorf("tor-driver: identity requires non-root Linux UID and GID")
		}
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
	bridges, transports, err := validateBridgeConfig(cfg.UseBridges, cfg.Bridges, cfg.Transports, cfg.Sandbox, deps.Logger)
	if err != nil {
		return cfg, err
	}
	cfg.Bridges, cfg.Transports = bridges, transports
	return cfg, nil
}

func validateBridgeConfig(useBridges bool, bridges []Bridge, transports []TransportConfig, sandbox SandboxMode, logger Logger) ([]Bridge, []TransportConfig, error) {
	bridges = append([]Bridge(nil), bridges...)
	transports = append([]TransportConfig(nil), transports...)
	registered := false
	for _, p := range transports {
		if p.Kind != Obfs4 {
			return nil, nil, ErrUnsupportedTransport
		}
		if registered {
			return nil, nil, fmt.Errorf("tor-driver: duplicate obfs4 registration")
		}
		if !filepath.IsAbs(p.Executable) || !safeText(p.Executable) || strings.ContainsAny(p.Executable, " \t\"") {
			return nil, nil, fmt.Errorf("tor-driver: transport executable must be an absolute path without whitespace or quotes")
		}
		registered = true
	}
	if sandbox == LinuxSandbox && registered {
		return nil, nil, fmt.Errorf("tor-driver: starter sandbox mode does not launch transports")
	}
	accepted := make([]Bridge, 0, len(bridges))
	for i, b := range bridges {
		if b.Transport != Plain && b.Transport != Obfs4 {
			logger.Warnf("tor-driver: ignoring unsupported bridge at index %d", i)
			continue
		}
		if _, err := numericEndpoint(b.Address, false); err != nil {
			return nil, nil, fmt.Errorf("tor-driver: bridge %d needs numeric IP:port", i)
		}
		if b.Fingerprint != "" && !validFingerprint(b.Fingerprint) {
			return nil, nil, fmt.Errorf("tor-driver: bridge %d fingerprint invalid", i)
		}
		if b.Transport == Obfs4 {
			if !registered {
				return nil, nil, fmt.Errorf("tor-driver: obfs4 bridge needs registered obfs4 executable")
			}
			cert, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(b.Obfs4Certificate, "="))
			if err != nil || len(cert) != 52 || b.IAT > IATParanoid || b.Fingerprint == "" {
				return nil, nil, fmt.Errorf("tor-driver: invalid obfs4 bridge %d", i)
			}
			b.Obfs4Certificate = base64.RawStdEncoding.EncodeToString(cert)
		} else if b.Obfs4Certificate != "" || b.IAT != IATDisabled {
			return nil, nil, fmt.Errorf("tor-driver: obfs4 options on plain bridge")
		}
		accepted = append(accepted, b)
	}
	if useBridges && len(accepted) == 0 {
		return nil, nil, fmt.Errorf("tor-driver: bridge mode has no supported bridges")
	}
	if !useBridges && len(accepted) > 0 {
		return nil, nil, fmt.Errorf("tor-driver: bridges require UseBridges")
	}
	return accepted, transports, nil
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
		if br.Transport == Obfs4 {
			v = "obfs4 " + v
		}
		if br.Fingerprint != "" {
			v += " " + string(br.Fingerprint)
		}
		if br.Transport == Obfs4 {
			v += " cert=" + br.Obfs4Certificate + " iat-mode=" + strconv.Itoa(int(br.IAT))
		}
		lines = append(lines, v)
	}
	return lines
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

func renderConfig(c Config, work, state, proxy, user, password string, pid int) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%s %s\n", k, v) }
	line("DataDirectory", quote(state))
	line("RunAsDaemon", "0")
	line("ControlPort", "127.0.0.1:auto")
	line("ControlPortWriteToFile", quote(filepath.Join(work, "control-port")))
	line("CookieAuthentication", "1")
	line("CookieAuthFile", quote(filepath.Join(work, "control-cookie")))
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
	line("NoExec", strconv.Itoa(bit(len(c.Transports) == 0)))
	line("Sandbox", strconv.Itoa(bit(c.Sandbox == LinuxSandbox)))
	levels := []string{"notice", "warn", "err"}
	line("Log", levels[c.LogLevel]+" stdout")
	line("ConnectionPadding", []string{"auto", "1", "auto", "0"}[c.ConnectionPadding])
	line("ReducedConnectionPadding", strconv.Itoa(bit(c.ConnectionPadding == ReducedConnectionPadding)))
	line("CircuitPadding", strconv.Itoa(bit(c.CircuitPadding != DisableCircuitPadding)))
	line("ReducedCircuitPadding", strconv.Itoa(bit(c.CircuitPadding == ReducedCircuitPadding)))
	line("ClientUseIPv4", strconv.Itoa(bit(c.ClientIP != ClientIPv6Only)))
	line("ClientUseIPv6", strconv.Itoa(bit(c.ClientIP != ClientIPv4Only)))
	if c.ClientIP == ClientPreferIPv6 || c.ClientIP == ClientIPv6Only {
		line("ClientPreferIPv6ORPort", "1")
	} else {
		line("ClientPreferIPv6ORPort", "auto")
	}
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
	for _, t := range c.Transports {
		line("ClientTransportPlugin", "obfs4 exec "+t.Executable)
	}
	for _, bridge := range bridgeLines(c.Bridges) {
		line("Bridge", bridge)
	}
	return b.String()
}
