package kubernetes

import (
	"os"
)

// SecurityContext represents Pod security context settings
type SecurityContext struct {
	RunAsUser    int
	RunAsGroup   int
	RunAsNonRoot bool
	ReadOnlyRoot bool
}

// GetSecurityContext detects the pod security context from current process
func GetSecurityContext() SecurityContext {
	ctx := SecurityContext{}

	// Get current UID and GID
	ctx.RunAsUser = os.Getuid()
	ctx.RunAsGroup = os.Getgid()

	// Check if running as non-root
	ctx.RunAsNonRoot = (ctx.RunAsUser != 0)

	// Test if root filesystem is read-only
	ctx.ReadOnlyRoot = isRootFilesystemReadOnly()

	return ctx
}

// isRootFilesystemReadOnly tests if the root filesystem is mounted read-only
func isRootFilesystemReadOnly() bool {
	// Try to create a test file in root
	testFile := "/.capsule-test"
	file, err := os.Create(testFile)
	if err != nil {
		// Cannot create in root - likely read-only
		return true
	}

	// File created - root is writable
	file.Close()
	os.Remove(testFile)
	return false
}
