// Command pt-fixture is a controlled managed-transport failure fixture. It is
// built only into the private Docker image; it is not a transport.
package main

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	mode := filepath.Base(os.Args[0])
	state := os.Getenv("TOR_PT_STATE_LOCATION")
	_ = os.MkdirAll(state, 0700)
	proxy, proxyErr := url.Parse(os.Getenv("TOR_PT_PROXY"))
	proxyScheme := ""
	proxyAuthenticated := false
	if proxyErr == nil && proxy != nil {
		proxyScheme = proxy.Scheme
		if proxy.User != nil {
			_, hasPassword := proxy.User.Password()
			proxyAuthenticated = proxy.User.Username() != "" && hasPassword
		}
	}
	metadata := fmt.Sprintf("proxy_present=%t\nproxy_scheme=%s\nproxy_authenticated=%t\nuid=%d\ngid=%d\n", os.Getenv("TOR_PT_PROXY") != "", proxyScheme, proxyAuthenticated, os.Geteuid(), os.Getegid())

	switch mode {
	case "pt-crash":
		writeReport(state, mode, metadata)
		os.Exit(42)
	case "pt-no-proxy":
		writeReport(state, mode, metadata)
		fmt.Println("VERSION 1")
		// Deliberately omit the required PROXY line.
		fmt.Println("CMETHOD obfs4 socks5 127.0.0.1:1")
		fmt.Println("CMETHODS DONE")
		time.Sleep(30 * time.Second)
	case "pt-escape", "lyrebird":
		report := metadata
		report += probeCapabilities()
		report += probeCgroupEscape()
		report += probe("ipv4", "tcp4", "192.0.2.1:9")
		report += probe("ipv6", "tcp6", "[2001:db8::1]:9")
		report += probeDNS()
		writeReport(state, mode, report)
		fmt.Println("VERSION 1")
		fmt.Println("PROXY-ERROR controlled-fixture")
	default:
		os.Exit(64)
	}
}

func probeCapabilities() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "ambient_capabilities_unknown=true\neffective_capabilities_unknown=true\n"
	}
	values := map[string]bool{"CapAmb:": false, "CapEff:": false}
	found := map[string]bool{"CapAmb:": false, "CapEff:": false}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		if _, ok := values[fields[0]]; !ok {
			continue
		}
		value, parseErr := strconv.ParseUint(fields[1], 16, 64)
		if parseErr != nil {
			continue
		}
		values[fields[0]] = value != 0
		found[fields[0]] = true
	}
	return fmt.Sprintf(
		"ambient_capabilities=%t\neffective_capabilities=%t\nambient_capabilities_unknown=%t\neffective_capabilities_unknown=%t\n",
		values["CapAmb:"], values["CapEff:"], !found["CapAmb:"], !found["CapEff:"],
	)
}

func probeCgroupEscape() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "cgroup_escape_attempted=false\ncgroup_escape_denied=false\n"
	}
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		parent := filepath.Dir(filepath.Join("/sys/fs/cgroup", filepath.Clean("/"+path)))
		err = os.WriteFile(filepath.Join(parent, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600)
		return fmt.Sprintf("cgroup_escape_attempted=true\ncgroup_escape_denied=%t\n", err != nil)
	}
	return "cgroup_escape_attempted=false\ncgroup_escape_denied=false\n"
}

func probe(name, network, address string) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if conn != nil {
		_ = conn.Close()
	}
	return fmt.Sprintf("%s_denied=%t\n", name, err != nil)
}

func probeDNS() string {
	attempted := false
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		attempted = true
		return (&net.Dialer{}).DialContext(ctx, "udp4", "192.0.2.53:53")
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := resolver.LookupHost(ctx, "escape.invalid")
	return fmt.Sprintf("dns_attempted=%t\ndns_denied=%t\n", attempted, err != nil)
}

func writeReport(state, mode, report string) {
	if state == "" || strings.ContainsAny(mode, `/\\`) {
		return
	}
	_ = os.WriteFile(filepath.Join(state, mode+".report"), []byte(report), 0600)
}
