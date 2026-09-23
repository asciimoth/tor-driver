package tordriver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/asciimoth/tor-driver/internal/control"
)

// GenerateClientAuthorization creates a protected-service credential with the
// Driver's injected entropy source.
func (d *Driver) GenerateClientAuthorization(name string) (ClientAuthorization, error) {
	d.mu.Lock()
	closed := d.closed
	d.mu.Unlock()
	if closed {
		return ClientAuthorization{}, ErrClosed
	}
	d.randomMu.Lock()
	defer d.randomMu.Unlock()
	return GenerateClientAuthorization(d.deps.Random, name)
}

// AddClientAuthorization lets this Driver access one protected v3 service.
// The credential is ephemeral and is removed when the owned Tor process exits.
func (d *Driver) AddClientAuthorization(ctx context.Context, address string, authorization ClientAuthorization) error {
	id, err := normalizeOnionAddress(address)
	if err != nil {
		return err
	}
	if err = validateClientAuthorization(authorization); err != nil {
		return err
	}
	private, err := authorization.PrivateKey.MarshalText()
	if err != nil {
		return err
	}
	command := "ONION_CLIENT_AUTH_ADD " + id + " x25519:" + string(private)
	clear(private)
	if authorization.Name != "" {
		command += " ClientName=" + authorization.Name
	}
	_, err = d.command(ctx, command)
	var rejected *control.Error
	if errors.As(err, &rejected) && (rejected.Code == 251 || rejected.Code == 252) {
		return nil
	}
	return err
}

// RemoveClientAuthorization removes a client-side credential. It is
// idempotent when Tor reports that no credential exists.
func (d *Driver) RemoveClientAuthorization(ctx context.Context, address string) error {
	id, err := normalizeOnionAddress(address)
	if err != nil {
		return err
	}
	_, err = d.command(ctx, "ONION_CLIENT_AUTH_REMOVE "+id)
	var rejected *control.Error
	if errors.As(err, &rejected) && rejected.Code == 251 {
		return nil
	}
	return err
}

func normalizeOnionAddress(address string) (string, error) {
	id := strings.ToLower(strings.TrimSuffix(address, ".onion"))
	if !validServiceID(id) {
		return "", fmt.Errorf("tor-driver: invalid v3 onion address")
	}
	return id, nil
}
