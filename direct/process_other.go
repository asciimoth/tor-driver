//go:build !linux && !windows

package direct

import (
	"fmt"
	tor "github.com/asciimoth/tor-driver"
	"os/exec"
)

func privatePermissions(string) error {
	return fmt.Errorf("direct: supported platforms are Linux and Windows")
}
func startProcess(*exec.Cmd, *tor.Identity) (tor.Process, error) {
	return nil, fmt.Errorf("direct: supported platforms are Linux and Windows")
}
