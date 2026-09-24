//go:build linux

package direct

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/unix"
)

const processCleanupTimeout = 2 * time.Second

func privatePermissions(path string) error { return os.Chmod(path, 0700) }

type processCgroup struct {
	path string
	fd   int
	once sync.Once
	err  error
}

func currentCgroupParent() (string, error) {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		path, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		path = filepath.Clean("/" + path)
		return filepath.Join("/sys/fs/cgroup", path), nil
	}
	return "", fmt.Errorf("direct: cgroup v2 hierarchy not found")
}

func resolveCgroupParent(parent string) (string, error) {
	if parent != "" {
		return parent, nil
	}
	return currentCgroupParent()
}

func cgroupParentWritable(parent string) (bool, error) {
	fd, err := unix.Open(filepath.Join(parent, "cgroup.procs"), unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		return true, unix.Close(fd)
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return false, nil
	}
	return false, err
}

func newProcessCgroup(parent string, required bool) (*processCgroup, error) {
	var err error
	parent, err = resolveCgroupParent(parent)
	if err != nil {
		if required {
			return nil, err
		}
		return nil, nil
	}
	if !filepath.IsAbs(parent) {
		return nil, fmt.Errorf("direct: cgroup parent must be absolute")
	}
	var st unix.Statfs_t
	if err := unix.Statfs(parent, &st); err != nil || uint64(st.Type) != unix.CGROUP2_SUPER_MAGIC {
		if required {
			return nil, errors.Join(fmt.Errorf("direct: cgroup parent is not on cgroup v2"), err)
		}
		return nil, nil
	}
	path, err := os.MkdirTemp(parent, "tor-driver-")
	if err != nil {
		if required {
			return nil, fmt.Errorf("direct: create delegated cgroup: %w", err)
		}
		return nil, nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	if required {
		if _, err = os.Stat(filepath.Join(path, "cgroup.kill")); err != nil {
			_ = unix.Close(fd)
			_ = os.Remove(path)
			return nil, fmt.Errorf("direct: cgroup.kill is required for containment: %w", err)
		}
	}
	return &processCgroup{path: path, fd: fd}, nil
}

func (c *processCgroup) pathAndLevel() (string, int) {
	rel := strings.TrimPrefix(filepath.Clean(c.path), "/sys/fs/cgroup/")
	parts := strings.Split(rel, string(filepath.Separator))
	return rel, len(parts)
}

func (c *processCgroup) kill() error {
	if c == nil {
		return nil
	}
	err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0600)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (c *processCgroup) waitEmpty() error {
	if c == nil {
		return nil
	}
	deadline := time.Now().Add(processCleanupTimeout)
	for {
		data, err := os.ReadFile(filepath.Join(c.path, "cgroup.events"))
		if err != nil {
			return err
		}
		if cgroupEventsEmpty(data) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("direct: cgroup remained populated after kill")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cgroupEventsEmpty(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "populated 0" {
			return true
		}
	}
	return false
}

func (c *processCgroup) empty() (bool, error) {
	if c == nil {
		return true, nil
	}
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.events"))
	if errors.Is(err, os.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return cgroupEventsEmpty(data), nil
}

func (c *processCgroup) close() error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		c.err = errors.Join(c.kill(), c.waitEmpty(), unix.Close(c.fd), os.Remove(c.path))
	})
	return c.err
}

func startProcess(cmd *exec.Cmd, id *tor.Identity) (tor.Process, error) {
	cgroup, err := newProcessCgroup("", false)
	if err != nil {
		return nil, err
	}
	return startProcessInCgroup(cmd, id, cgroup)
}

func startProcessInCgroup(cmd *exec.Cmd, id *tor.Identity, cgroup *processCgroup) (tor.Process, error) {
	if os.Geteuid() == 0 && id == nil {
		_ = cgroup.close()
		return nil, fmt.Errorf("direct: root caller must configure a non-root UID/GID")
	}
	pidfd := -1
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, PidFD: &pidfd}
	if cgroup != nil {
		cmd.SysProcAttr.UseCgroupFD = true
		cmd.SysProcAttr.CgroupFD = cgroup.fd
	}
	if id != nil {
		if id.UID == 0 || id.GID == 0 {
			_ = cgroup.close()
			return nil, fmt.Errorf("direct: refusing root identity")
		}
		if os.Geteuid() == 0 {
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: id.UID, Gid: id.GID, Groups: []uint32{}}
		} else if uint32(os.Geteuid()) != id.UID || uint32(os.Getegid()) != id.GID {
			_ = cgroup.close()
			return nil, fmt.Errorf("direct: insufficient privilege to set requested identity")
		}
	}
	if err := cmd.Start(); err != nil {
		_ = cgroup.close()
		return nil, err
	}
	var pidfdMu sync.Mutex
	groupKill := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	pidfdKill := func() error {
		pidfdMu.Lock()
		defer pidfdMu.Unlock()
		if pidfd < 0 {
			return nil
		}
		err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	kill := func() error {
		return errors.Join(cgroup.kill(), pidfdKill(), groupKill())
	}
	release := func() error {
		err := errors.Join(cgroup.kill(), groupKill(), cgroup.waitEmpty())
		pidfdMu.Lock()
		if pidfd >= 0 {
			err = errors.Join(err, unix.Close(pidfd))
			pidfd = -1
		}
		pidfdMu.Unlock()
		err = errors.Join(err, cgroup.close())
		return err
	}
	return &process{cmd: cmd, kill: kill, release: release}, nil
}
