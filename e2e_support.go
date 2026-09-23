//go:build e2e

package tordriver

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// IsolationCircuit is test-only circuit evidence from a controlled Tor
// network. It is available only in e2e builds and must not be used by
// applications as a circuit-pinning API.
type IsolationCircuit struct {
	ID       string
	Username string
	Password string
}

// TestIsolationToken returns the SOCKS isolation password used by this Network.
// It is available only for deterministic controlled-network tests.
func (n *Network) TestIsolationToken() string { return n.id }

// TestIsolationCircuits reads bounded circuit status for deterministic e2e
// assertions. It returns only circuits that contain SOCKS credentials.
func (d *Driver) TestIsolationCircuits(ctx context.Context) ([]IsolationCircuit, error) {
	r, err := d.command(ctx, "GETINFO circuit-status")
	if err != nil {
		return nil, err
	}
	var result []IsolationCircuit
	for _, line := range r.Lines {
		line = strings.TrimPrefix(line, "circuit-status=")
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] == "OK" {
			continue
		}
		circuit := IsolationCircuit{ID: fields[0]}
		for _, field := range fields[2:] {
			if value, ok := strings.CutPrefix(field, "SOCKS_USERNAME="); ok {
				circuit.Username, err = isolationValue(value)
			} else if value, ok := strings.CutPrefix(field, "SOCKS_PASSWORD="); ok {
				circuit.Password, err = isolationValue(value)
			}
			if err != nil {
				return nil, err
			}
		}
		if circuit.Username != "" || circuit.Password != "" {
			result = append(result, circuit)
		}
	}
	return result, nil
}

func isolationValue(value string) (string, error) {
	if !strings.HasPrefix(value, `"`) {
		return value, nil
	}
	decoded, err := strconv.Unquote(value)
	if err != nil {
		return "", fmt.Errorf("tor-driver: invalid isolation value: %w", err)
	}
	return decoded, nil
}
