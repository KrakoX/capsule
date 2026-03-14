//go:build linux

package syscall

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// SyscallTest represents a tested syscall
type SyscallTest struct {
	Name    string
	Number  uintptr
	Allowed bool
}

// DangerousSyscalls are syscalls that enable privilege escalation or escape
var DangerousSyscalls = map[string]uintptr{
	"mount":      unix.SYS_MOUNT,
	"umount2":    unix.SYS_UMOUNT2,
	"ptrace":     unix.SYS_PTRACE,
	"reboot":     unix.SYS_REBOOT,
	"setns":      unix.SYS_SETNS,
	"unshare":    unix.SYS_UNSHARE,
	"pivot_root": unix.SYS_PIVOT_ROOT,
	"chroot":     unix.SYS_CHROOT,
	"setuid":     unix.SYS_SETUID,
	"setgid":     unix.SYS_SETGID,
}

// TestDangerousSyscalls tests if dangerous syscalls are blocked
// by seccomp or other security mechanisms
func TestDangerousSyscalls() []SyscallTest {
	var results []SyscallTest

	for name, num := range DangerousSyscalls {
		test := SyscallTest{
			Name:    name,
			Number:  num,
			Allowed: testSyscall(num),
		}
		results = append(results, test)
	}

	return results
}

// testSyscall tests if a syscall is blocked by attempting to call it
// with invalid arguments (won't actually execute dangerous operation)
func testSyscall(num uintptr) bool {
	_, _, errno := syscall.RawSyscall(num, 0, 0, 0)

	// EPERM (1) or ENOSYS (38) = blocked by seccomp or lack of capability
	// Any other errno (including success) = syscall is allowed
	return errno != syscall.EPERM && errno != syscall.ENOSYS
}

// CountAllowed returns the number of allowed dangerous syscalls
func CountAllowed(tests []SyscallTest) int {
	count := 0
	for _, t := range tests {
		if t.Allowed {
			count++
		}
	}
	return count
}

// GetAllowed returns only allowed syscalls
func GetAllowed(tests []SyscallTest) []SyscallTest {
	var allowed []SyscallTest
	for _, t := range tests {
		if t.Allowed {
			allowed = append(allowed, t)
		}
	}
	return allowed
}

// GetBlocked returns only blocked syscalls
func GetBlocked(tests []SyscallTest) []SyscallTest {
	var blocked []SyscallTest
	for _, t := range tests {
		if !t.Allowed {
			blocked = append(blocked, t)
		}
	}
	return blocked
}
