//go:build !linux

package syscall

// SyscallTest represents a tested syscall.
type SyscallTest struct {
	Name    string
	Number  uintptr
	Allowed bool
}

// TestDangerousSyscalls is a no-op on non-Linux platforms.
func TestDangerousSyscalls() []SyscallTest { return nil }

// GetAllowed returns only allowed syscalls.
func GetAllowed(tests []SyscallTest) []SyscallTest {
	var allowed []SyscallTest
	for _, t := range tests {
		if t.Allowed {
			allowed = append(allowed, t)
		}
	}
	return allowed
}

// GetBlocked returns only blocked syscalls.
func GetBlocked(tests []SyscallTest) []SyscallTest {
	var blocked []SyscallTest
	for _, t := range tests {
		if !t.Allowed {
			blocked = append(blocked, t)
		}
	}
	return blocked
}

// CountAllowed returns the number of allowed dangerous syscalls.
func CountAllowed(tests []SyscallTest) int {
	count := 0
	for _, t := range tests {
		if t.Allowed {
			count++
		}
	}
	return count
}
