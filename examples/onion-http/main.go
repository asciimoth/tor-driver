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
	"github.com/asciimoth/tor-driver/direct"
)

func main() {
	path := flag.String("tor", "", "absolute path to Tor; empty searches PATH")
	uid := flag.Uint("uid", 0, "Linux UID when invoked as root")
	gid := flag.Uint("gid", 0, "Linux GID when invoked as root")
	flag.Parse()
	cfg := tor.Config{TorExecutable: *path}
	if *uid != 0 || *gid != 0 {
		cfg.Identity = &tor.Identity{UID: uint32(*uid), GID: uint32(*gid)}
	}
	if err := run(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(cfg tor.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	logger := direct.NewLogger(os.Stderr)
	serverSystem, serverCfg, err := direct.NewBestEffortSystem(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = serverSystem.Close() }()
	clientSystem, clientCfg, err := direct.NewBestEffortSystem(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = clientSystem.Close() }()
	serverDriver, err := tor.Start(ctx, serverCfg, serverSystem.Dependencies(direct.Network(), direct.Network(), logger))
	if err != nil {
		return err
	}
	defer func() { _ = serverDriver.Close() }()
	clientDriver, err := tor.Start(ctx, clientCfg, clientSystem.Dependencies(direct.Network(), direct.Network(), logger))
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
		if err = (direct.System{}).Sleep(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("waiting for onion publication: %w", err)
		}
	}
}
