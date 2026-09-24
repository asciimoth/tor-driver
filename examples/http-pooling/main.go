// Command http-pooling shows that circuit isolation and HTTP connection reuse
// are separate choices.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/direct"
)

func run() error {
	torPath := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	url := flag.String("url", "https://check.torproject.org/", "HTTP URL to request through Tor")
	fresh := flag.Bool("fresh-connection", false, "disable HTTP keep-alives and isolate each Tor connection")
	flag.Parse()
	system, cfg, err := direct.NewBestEffortSystem(tor.Config{TorExecutable: *torPath})
	if err != nil {
		return err
	}
	defer func() { _ = system.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	driver, err := tor.Start(ctx, cfg, system.Dependencies(direct.Network(), direct.Network(), direct.NewLogger(os.Stderr)))
	if err != nil {
		return err
	}
	defer func() { _ = driver.Close() }()
	if err = driver.WaitReady(ctx); err != nil {
		return err
	}
	policy := tor.SessionCircuits
	if *fresh {
		policy = tor.IsolateEachConnection
	}
	network, err := driver.NewNetwork(tor.NetworkConfig{Circuits: policy})
	if err != nil {
		return err
	}
	defer func() { _ = network.Close() }()
	transport := &http.Transport{DialContext: network.Dial, Proxy: nil, DisableKeepAlives: *fresh}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Minute}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, *url, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	_, err = io.Copy(io.Discard, response.Body)
	if err == nil {
		fmt.Println(response.Status)
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
