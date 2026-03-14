package filesystem

import (
	"os"
	"path/filepath"
)

// WritableDirectory represents a writable directory that could be exploited
type WritableDirectory struct {
	Path      string
	Sensitive bool   // True if in a sensitive location
	Reason    string // Why it's notable
}

// CheckWritableDirectories tests common directories for write access
func CheckWritableDirectories() []WritableDirectory {
	testDirs := []string{
		"/tmp",
		"/var/tmp",
		"/dev/shm",
		"/home",
		"/root",
		"/etc",
		"/var/log",
		"/opt",
		"/usr/local",
	}

	var writable []WritableDirectory

	for _, dir := range testDirs {
		if isWritable(dir) {
			wd := WritableDirectory{
				Path: dir,
			}

			// Mark sensitive directories
			switch dir {
			case "/etc":
				wd.Sensitive = true
				wd.Reason = "system configuration"
			case "/root":
				wd.Sensitive = true
				wd.Reason = "root home directory"
			case "/var/log":
				wd.Sensitive = true
				wd.Reason = "system logs"
			case "/usr/local":
				wd.Sensitive = true
				wd.Reason = "system binaries"
			case "/tmp", "/var/tmp", "/dev/shm":
				wd.Reason = "temporary storage (expected)"
			default:
				wd.Reason = "writable"
			}

			writable = append(writable, wd)
		}
	}

	return writable
}

// isWritable tests if a directory is writable by creating a test file
func isWritable(dir string) bool {
	// Check if directory exists
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return false
	}

	// Try to create a test file
	testFile := filepath.Join(dir, ".capsule-test")
	file, err := os.Create(testFile)
	if err != nil {
		return false
	}

	// Clean up
	file.Close()
	os.Remove(testFile)

	return true
}

// GetSensitiveWritable returns only sensitive writable directories
func GetSensitiveWritable(dirs []WritableDirectory) []WritableDirectory {
	var sensitive []WritableDirectory
	for _, d := range dirs {
		if d.Sensitive {
			sensitive = append(sensitive, d)
		}
	}
	return sensitive
}

// HasSensitiveWritable checks if any sensitive directories are writable
func HasSensitiveWritable(dirs []WritableDirectory) bool {
	for _, d := range dirs {
		if d.Sensitive {
			return true
		}
	}
	return false
}
