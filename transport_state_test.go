package tordriver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/asciimoth/gobox"
	"github.com/asciimoth/gobox/debug"
)

// This key is part of the on-disk v1 format. Keep it stable across releases.
func TestBridgeRouteKeyV1(t *testing.T) {
	b := Bridge{Transport: "sample", Address: "192.0.2.1:443",
		Fingerprint: Fingerprint(strings.Repeat("ab", 20)),
		Args:        map[string]string{"z": "two words", "a": "\xff\x00"}}
	key := bridgeRouteKey(b)
	if got := hex.EncodeToString(key[:]); got != "672cf50c9bd20fbe3aa3d71005d3e88af33601bdecf1834dd792f0bb3b25b2f0" {
		t.Fatalf("v1 bridge key changed: %s", got)
	}
}

type routeTestFiles struct {
	gobox.Files
	renameErr error
}

func (f *routeTestFiles) Rename(ctx context.Context, from, to string) error {
	if f.renameErr != nil {
		return f.renameErr
	}
	return f.Files.Rename(ctx, from, to)
}

func TestPersistentBridgeRouteAssignments(t *testing.T) {
	ctx := context.Background()
	backend, err := debug.New(debug.Config{
		Root: t.TempDir(), Programs: map[gobox.ProgramID]debug.Program{"test": {Executable: os.Args[0]}},
		Templates: map[gobox.TemplateID]debug.Template{"test": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	_, owner, err := backend.IssueAndBindOwner(ctx, gobox.Owner{Workspace: "test", Class: "test", Name: "routes"})
	if err != nil {
		t.Fatal(err)
	}
	box, err := owner.Acquire(ctx, "routes", "test")
	if err != nil {
		t.Fatal(err)
	}
	files, err := box.FS(gobox.Persistent)
	if err != nil {
		t.Fatal(err)
	}
	store := &routeTestFiles{Files: files}
	const file = "state/tor-driver-routes-v1"
	read := func() []byte {
		t.Helper()
		data, err := store.ReadFile(ctx, file, 4096)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var f *lifecycleFixture
	a := Bridge{Transport: "sample", Address: "192.0.2.1:443", Args: map[string]string{"secret": "fixture-option"}}
	b := Bridge{Transport: "sample", Address: "[2001:db8::1]:443"}
	c := Bridge{Transport: "sample", Address: "192.0.2.3:443"}
	methods := []TransportConfig{{Kind: "sample", Dial: passthrough}}
	start := func(registrations []TransportConfig, bridges ...Bridge) (*Driver, error) {
		t.Helper()
		f = newLifecycleFixture(t, "")
		f.deps.Clock = fixtureClock{timeout: 5 * time.Second}
		f.deps.Sandboxes.(*fixtureSandboxes).box.persistentFiles = store
		f.cfg.StateDirectory = gobox.Path{Root: gobox.Persistent, Rel: "state"}
		f.cfg.UseBridges = len(bridges) > 0
		f.cfg.Bridges = bridges
		f.cfg.Transports = registrations
		d, err := Start(ctx, f.cfg, f.deps)
		if err == nil {
			t.Cleanup(func() { _ = d.Close() })
		}
		return d, err
	}
	d, err := start(methods, a, b)
	if err != nil {
		t.Fatal(err)
	}
	firstA, firstB := d.cfg.Bridges[0].route, d.cfg.Bridges[1].route
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	original := string(read())
	err = d.SetBridges(ctx, BridgeConfig{UseBridges: true, Bridges: []Bridge{c}})
	if !errors.Is(err, ErrClosed) || string(read()) != original {
		t.Fatalf("closed driver accepted or persisted a new bridge: %v", err)
	}
	if original == "" || strings.Contains(original, a.Address) || strings.Contains(original, a.Args["secret"]) {
		t.Fatal("missing record or plaintext bridge data")
	}
	d, err = start(methods, b, a)
	if err != nil {
		t.Fatal(err)
	}
	if d.cfg.Bridges[0].route != firstB || d.cfg.Bridges[1].route != firstA || string(read()) != original {
		t.Fatal("restart changed the assignment of a reordered bridge")
	}

	store.renameErr = errFixture
	before := len(f.processes.commandLines())
	err = d.SetBridges(ctx, BridgeConfig{UseBridges: true, Bridges: []Bridge{c}})
	if !errors.Is(err, errFixture) || len(f.processes.commandLines()) != before || string(read()) != original || d.gate.routes[firstA].bridge.Address != a.Address {
		t.Fatal("failed route save changed Tor, the active routes, or the saved assignments")
	}
	if _, err := store.Stat(ctx, file+".tmp"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temporary file after failed route save: %v", err)
	}
	store.renameErr = nil
	if err := d.SetBridges(ctx, BridgeConfig{UseBridges: true, Bridges: []Bridge{c, b}}); err != nil {
		t.Fatal(err)
	}
	firstC := d.cfg.Bridges[0].route
	if firstC == firstA || d.cfg.Bridges[1].route != firstB {
		t.Fatal("replacement reused a retired address or moved an active bridge")
	}
	if err := d.SetBridges(ctx, BridgeConfig{UseBridges: true, Bridges: []Bridge{a}}); err != nil {
		t.Fatal(err)
	}
	secondA := d.cfg.Bridges[0].route
	if secondA == firstA {
		t.Fatal("reactivated a retired route")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d, err = start(methods)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetBridges(ctx, BridgeConfig{UseBridges: true, Bridges: []Bridge{a, c}}); err != nil {
		t.Fatal(err)
	}
	if d.cfg.Bridges[0].route != secondA || d.cfg.Bridges[1].route != firstC {
		t.Fatal("standby startup lost runtime assignments")
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	saved := read()
	d, err = start(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetOutbound(&dialNetwork{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("retired route reached outbound after restart without Go transports")
		return nil, nil
	}}); err != nil {
		t.Fatal(err)
	}
	client, peer := net.Pipe()
	defer func() { _ = client.Close(); _ = peer.Close() }()
	for _, route := range []string{firstA, firstB} {
		if _, _, err := d.gate.dial(ctx, client, route); !errors.Is(err, ErrUnsupportedTransport) {
			t.Fatalf("retired route %q: %v", route, err)
		}
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	for _, damaged := range [][]byte{saved[:1], saved[:len(saved)-sha256.Size], bytes.Repeat([]byte{1}, len(saved))} {
		if err := store.WriteFile(ctx, file, damaged, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := start(methods, a); err == nil || f.processes.process() != nil {
			t.Fatal("started Tor with damaged route assignments")
		}
	}
}
