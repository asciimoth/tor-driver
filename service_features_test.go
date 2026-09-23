package tordriver

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type memoryOnionKeys struct {
	mu       sync.Mutex
	keys     map[string]OnionServiceKey
	storeErr error
}

func (s *memoryOnionKeys) Load(_ context.Context, name string) (OnionServiceKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.keys[name]
	if !ok {
		return OnionServiceKey{}, fs.ErrNotExist
	}
	return key, nil
}

func (s *memoryOnionKeys) Store(_ context.Context, name string, key OnionServiceKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.storeErr != nil {
		return s.storeErr
	}
	if s.keys == nil {
		s.keys = make(map[string]OnionServiceKey)
	}
	if _, exists := s.keys[name]; exists {
		return fs.ErrExist
	}
	s.keys[name] = key
	return nil
}

func TestPersistentServiceIdentityUsesInjectedStore(t *testing.T) {
	store := &memoryOnionKeys{}
	var firstAddress string
	for restart := 0; restart < 2; restart++ {
		f := newLifecycleFixture(t, "")
		f.deps.OnionKeys = store
		d, err := Start(context.Background(), f.cfg, f.deps)
		if err != nil {
			t.Fatal(err)
		}
		s, err := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80}, KeyName: "main"})
		if err != nil {
			t.Fatal(err)
		}
		if restart == 0 {
			firstAddress = s.Address()
			if _, duplicateErr := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{81}, KeyName: "main"}); duplicateErr == nil {
				t.Fatal("same key name was active twice in one Driver")
			}
		} else if s.Address() != firstAddress {
			t.Fatalf("persistent address changed: %s != %s", s.Address(), firstAddress)
		}
		commands := f.processes.commandLines()
		add := lastCommand(commands, "ADD_ONION ")
		if restart == 0 && !strings.HasPrefix(add, "ADD_ONION NEW:ED25519-V3") {
			t.Fatalf("first service did not generate a key: %s", add)
		}
		if restart == 1 && !strings.HasPrefix(add, "ADD_ONION ED25519-V3:") {
			t.Fatalf("restart did not load its key: %s", add)
		}
		if err = s.Close(); err != nil {
			t.Fatal(err)
		}
		if err = d.Close(); err != nil {
			t.Fatal(err)
		}
		f.processes.waitForServers(t)
	}
}

func TestPersistentServiceStoreFailureDeletesService(t *testing.T) {
	f := newLifecycleFixture(t, "")
	f.deps.OnionKeys = &memoryOnionKeys{storeErr: errFixture}
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80}, KeyName: "main"}); !errors.Is(err, errFixture) {
		t.Fatalf("NewService() error = %v", err)
	}
	commands := f.processes.commandLines()
	if lastCommand(commands, "DEL_ONION ") == "" {
		t.Fatal("service was not deleted after key storage failed")
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	f.processes.waitForServers(t)
}

func TestV3ClientAuthorizationCommands(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := d.GenerateClientAuthorization("alice")
	if err != nil {
		t.Fatal(err)
	}
	public, err := authorization.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.NewService(context.Background(), ServiceConfig{
		Ports: []uint16{80}, MaxStreams: 4, MaxStreamsPolicy: CloseRendezvousCircuit,
		AuthorizedClients: []ClientAuthorizationPublicKey{public},
	})
	if err != nil {
		t.Fatal(err)
	}
	hostCommand := lastCommand(f.processes.commandLines(), "ADD_ONION ")
	publicText, _ := public.MarshalText()
	for _, part := range []string{"Flags=V3Auth,MaxStreamsCloseCircuit", "MaxStreams=4", "ClientAuthV3=" + string(publicText)} {
		if !strings.Contains(hostCommand, part) {
			t.Fatalf("hosting command %q does not contain %q", hostCommand, part)
		}
	}
	if err = d.AddClientAuthorization(context.Background(), s.Address(), authorization); err != nil {
		t.Fatal(err)
	}
	accessCommand := lastCommand(f.processes.commandLines(), "ONION_CLIENT_AUTH_ADD ")
	if !strings.Contains(accessCommand, " x25519:") || !strings.Contains(accessCommand, " ClientName=alice") {
		t.Fatalf("invalid access command: %s", accessCommand)
	}
	if err = d.RemoveClientAuthorization(context.Background(), s.Address()); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	f.processes.waitForServers(t)
}

func TestServicePortRemovalReopenAndRollback(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80, 443}})
	if err != nil {
		t.Fatal(err)
	}
	l80, err := s.Listen(context.Background(), "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Listen(context.Background(), "tcp", ":443"); err != nil {
		t.Fatal(err)
	}
	initial := lastCommand(f.processes.commandLines(), "ADD_ONION ")
	oldEndpoint := commandPortTarget(initial, "80")
	if oldEndpoint == "" {
		t.Fatalf("initial mapping missing port 80: %s", initial)
	}
	if err = l80.Close(); err != nil {
		t.Fatal(err)
	}
	removed := lastCommand(f.processes.commandLines(), "ADD_ONION ")
	if strings.Contains(removed, "Port=80,") || !strings.Contains(removed, "Port=443,") {
		t.Fatalf("incorrect mapping after removal: %s", removed)
	}
	l80, err = s.Listen(context.Background(), "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	reopened := lastCommand(f.processes.commandLines(), "ADD_ONION ")
	newEndpoint := commandPortTarget(reopened, "80")
	if newEndpoint == "" || newEndpoint == oldEndpoint {
		t.Fatalf("reopened port reused a released target: old=%s new=%s", oldEndpoint, newEndpoint)
	}

	f.processes.rejectNextAdd()
	if err = l80.Close(); err == nil {
		t.Fatal("mapping update rejection was ignored")
	}
	rollback := lastCommand(f.processes.commandLines(), "ADD_ONION ")
	if commandPortTarget(rollback, "80") != newEndpoint || !strings.Contains(rollback, "Port=443,") {
		t.Fatalf("old mapping was not restored: %s", rollback)
	}
	client, err := net.DialTimeout("tcp", newEndpoint, time.Second)
	if err != nil {
		t.Fatalf("retained backing listener is unavailable: %v", err)
	}
	accepted, err := l80.Accept()
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	_ = accepted.Close()
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = d.Close(); err != nil {
		t.Fatal(err)
	}
	f.processes.waitForServers(t)
}

func TestServicePublicationEventsAndCancellation(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80}})
	if err != nil {
		t.Fatal(err)
	}
	events, cancelEvents, err := s.SubscribeEvents(2)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelEvents()
	if initial := (<-events).(PublicationEvent); initial.State != PublicationPending {
		t.Fatalf("initial publication state = %v", initial.State)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err = s.WaitPublished(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitPublished() error = %v", err)
	}
	f.processes.sendEvent(t, "HS_DESC UPLOADED "+strings.TrimSuffix(s.Address(), ".onion")+" NO_AUTH UNKNOWN")
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err = s.WaitPublished(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		publication, ok := event.(PublicationEvent)
		if !ok || publication.State != PublicationPublished {
			t.Fatalf("publication event = %#v", event)
		}
	case <-ctx.Done():
		t.Fatal("publication event was not delivered")
	}
	_ = s.Close()
	_ = d.Close()
	f.processes.waitForServers(t)
}

func TestServiceDrainAndCloseSubscription(t *testing.T) {
	f := newLifecycleFixture(t, "")
	d, err := Start(context.Background(), f.cfg, f.deps)
	if err != nil {
		t.Fatal(err)
	}
	s, err := d.NewService(context.Background(), ServiceConfig{Ports: []uint16{80}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := s.Listen(context.Background(), "tcp", ":80")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := commandPortTarget(lastCommand(f.processes.commandLines(), "ADD_ONION "), "80")
	client, err := net.DialTimeout("tcp", endpoint, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	if _, err = s.SubscribeCloser(closerFunc(func() error { close(closed); return nil })); err != nil {
		t.Fatal(err)
	}
	drained := make(chan error, 1)
	go func() { drained <- s.Drain(context.Background()) }()
	select {
	case err = <-drained:
		t.Fatalf("Drain returned with an accepted connection: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	waitCtx, cancelWait := context.WithTimeout(context.Background(), time.Second)
	defer cancelWait()
	if err = s.WaitPublished(waitCtx); !errors.Is(err, ErrClosed) {
		t.Fatalf("WaitPublished() during Drain error = %v", err)
	}
	_ = client.Close()
	_ = accepted.Close()
	select {
	case err = <-drained:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Drain did not finish")
	}
	select {
	case <-closed:
	default:
		t.Fatal("service close subscriber was not notified")
	}
	_ = d.Close()
	f.processes.waitForServers(t)
}

func lastCommand(commands []string, prefix string) string {
	for i := len(commands) - 1; i >= 0; i-- {
		if strings.HasPrefix(commands[i], prefix) {
			return commands[i]
		}
	}
	return ""
}

func commandPortTarget(command, port string) string {
	for _, field := range strings.Fields(command) {
		if target, ok := strings.CutPrefix(field, "Port="+port+","); ok {
			return target
		}
	}
	return ""
}

var _ OnionKeyStore = (*memoryOnionKeys)(nil)
