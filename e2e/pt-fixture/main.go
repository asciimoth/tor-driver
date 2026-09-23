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
	metadata := fmt.Sprintf("proxy_present=%t\nproxy_scheme=%s\nproxy_authenticated=%t\n", os.Getenv("TOR_PT_PROXY") != "", proxyScheme, proxyAuthenticated)

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
	case "pt-escape":
		report := metadata
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
