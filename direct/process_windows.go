//go:build windows

package direct

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"unsafe"

	tor "github.com/asciimoth/tor-driver"
	"golang.org/x/sys/windows"
)

// Restrict directory access to the current account and SYSTEM, removing
// inherited ACEs. Mode 0700 alone has no ACL meaning on Windows.
func privatePermissions(path string) error {
	sa, err := privateSecurityAttributes()
	if err != nil {
		return err
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(sa.SecurityDescriptor)
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func startProcess(cmd *exec.Cmd, id *tor.Identity) (tor.Process, error) {
	if id != nil {
		return nil, fmt.Errorf("direct: Linux UID/GID is not supported on Windows")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	// Assign the child while suspended so it cannot launch a PT outside the Job.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	cmd.SysProcAttr.HideWindow = true
	if err = cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	fail := func(e error) (tor.Process, error) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		return nil, e
	}
	if err != nil {
		return fail(err)
	}
	defer func() { _ = windows.CloseHandle(h) }()
	if err = windows.AssignProcessToJobObject(job, h); err != nil {
		return fail(err)
	}
	if err = resumeProcess(uint32(cmd.Process.Pid)); err != nil {
		return fail(err)
	}
	return &process{cmd: cmd, kill: func() error { return windows.TerminateJobObject(job, 1) }, release: func() error { return windows.CloseHandle(job) }}, nil
}

func resumeProcess(pid uint32) error {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(snapshot) }()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err = windows.Thread32First(snapshot, &entry); err != nil {
		return err
	}
	resumed := false
	for {
		if entry.OwnerProcessID == pid {
			thread, openErr := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if openErr != nil {
				return openErr
			}
			_, resumeErr := windows.ResumeThread(thread)
			closeErr := windows.CloseHandle(thread)
			if err = errors.Join(resumeErr, closeErr); err != nil {
				return err
			}
			resumed = true
		}
		err = windows.Thread32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return err
		}
	}
	if !resumed {
		return fmt.Errorf("direct: suspended process has no thread")
	}
	return nil
}
