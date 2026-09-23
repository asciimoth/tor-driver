//go:build windows

package direct

import (
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
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer func() { _ = token.Close() }()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
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
		windows.CloseHandle(job)
		return nil, err
	}
	// Assign the child while suspended so it cannot launch a PT outside the Job.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED, HideWindow: true}
	if err = cmd.Start(); err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_SUSPEND_RESUME, false, uint32(cmd.Process.Pid))
	fail := func(e error) (tor.Process, error) {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		return nil, e
	}
	if err != nil {
		return fail(err)
	}
	defer windows.CloseHandle(h)
	if err = windows.AssignProcessToJobObject(job, h); err != nil {
		return fail(err)
	}
	resume := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")
	if err = resume.Find(); err != nil {
		return fail(err)
	}
	status, _, _ := resume.Call(uintptr(h))
	if int32(status) < 0 {
		return fail(fmt.Errorf("direct: NtResumeProcess status 0x%x", status))
	}
	return &process{cmd: cmd, kill: func() error { return windows.TerminateJobObject(job, 1) }, release: func() error { return windows.CloseHandle(job) }}, nil
}
