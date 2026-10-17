// A complete two-process example. Install Tor on PATH or use -tor.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"github.com/asciimoth/tor-driver/examples/internal/debugtor"
)

func main() {
	path := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(executable string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	serverRuntime, err := debugtor.New(ctx, executable, "", "onion-http-server")
	if err != nil {
		return err
	}
	defer func() { _ = serverRuntime.Close() }()
	clientRuntime, err := debugtor.New(ctx, executable, "", "onion-http-client")
	if err != nil {
		return err
	}
	defer func() { _ = clientRuntime.Close() }()
	serverDriver, err := tor.Start(ctx, tor.Config{}, serverRuntime.Dependencies(debugtor.Network()))
	if err != nil {
		return err
	}
	defer func() { _ = serverDriver.Close() }()
	clientDriver, err := tor.Start(ctx, tor.Config{}, clientRuntime.Dependencies(debugtor.Network()))
	if err != nil {
		return err
	}
	defer func() { _ = clientDriver.Close() }()
	if err = serverDriver.WaitReady(ctx); err != nil {
		return err
	}
	if err = clientDriver.WaitReady(ctx); err != nil {
		return err
	}
	service, err := serverDriver.NewService(ctx, tor.ServiceConfig{Ports: []uint16{80}})
	if err != nil {
		return err
	}
	defer func() { _ = service.Close() }()
	listener, err := service.Listen(ctx, "tcp", ":80")
	if err != nil {
		return err
	}
	httpServer := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "hello through two owned Tor daemons")
	})}
	defer func() { _ = httpServer.Close() }()
	serveErr := make(chan error, 1)
	go func() { serveErr <- httpServer.Serve(listener) }()
	if err = service.WaitPublished(ctx); err != nil {
		return fmt.Errorf("waiting for onion publication: %w", err)
	}
	network, err := clientDriver.NewNetwork(tor.NetworkConfig{Circuits: tor.IsolateEachConnection})
	if err != nil {
		return err
	}
	defer func() { _ = network.Close() }()
	// An HTTP transport may reuse TCP connections. Disable keep-alives when
	// the desired policy is one Tor isolation group per HTTP request.
	transport := &http.Transport{DialContext: network.Dial, Proxy: nil, DisableKeepAlives: true, ForceAttemptHTTP2: false}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 45 * time.Second}
	url := "http://" + service.Address() + "/"
	fmt.Println("Serving", url)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, e := client.Do(req)
		if e == nil {
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			if readErr != nil {
				return readErr
			}
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("HTTP status %s", resp.Status)
			}
			fmt.Print(string(body))
			return nil
		}
		select {
		case e = <-serveErr:
			if !errors.Is(e, http.ErrServerClosed) {
				return e
			}
			return fmt.Errorf("server stopped")
		default:
		}
		// A client can still need time to fetch the newly uploaded descriptor.
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return fmt.Errorf("waiting for onion publication: %w", ctx.Err())
		}
	}
}
