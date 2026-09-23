//go:build linux

package direct

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	tor "github.com/asciimoth/tor-driver"
)

func privatePermissions(path string) error { return os.Chmod(path, 0700) }
func startProcess(cmd *exec.Cmd, id *tor.Identity) (tor.Process, error) {
	if os.Geteuid() == 0 && id == nil {
		return nil, fmt.Errorf("direct: root caller must configure a non-root UID/GID")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if id != nil {
		if id.UID == 0 || id.GID == 0 {
			return nil, fmt.Errorf("direct: refusing root identity")
		}
		if os.Geteuid() == 0 {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: id.UID, Gid: id.GID, Groups: []uint32{}}
		} else if uint32(os.Geteuid()) != id.UID || uint32(os.Getegid()) != id.GID {
			return nil, fmt.Errorf("direct: insufficient privilege to set requested identity")
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	kill := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	return &process{cmd: cmd, kill: kill, release: kill}, nil
}
