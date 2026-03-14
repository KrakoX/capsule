package security

import (
	"os"
	"strings"
)

// SeccompMode represents the seccomp enforcement mode
type SeccompMode string

const (
	SeccompDisabled  SeccompMode = "disabled"
	SeccompStrict    SeccompMode = "strict"
	SeccompFiltering SeccompMode = "filtering"
	SeccompUnknown   SeccompMode = "unknown"
)

// GetSeccompMode reads the seccomp mode from /proc/self/status
func GetSeccompMode() SeccompMode {
	status := readFileSeccomp("/proc/self/status")
	if status == "" {
		return SeccompUnknown
	}

	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "Seccomp:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				switch parts[1] {
				case "0":
					return SeccompDisabled
				case "1":
					return SeccompStrict
				case "2":
					return SeccompFiltering
				}
			}
		}
	}

	return SeccompUnknown
}

// IsSecure returns true if seccomp provides meaningful protection
func (sm SeccompMode) IsSecure() bool {
	return sm == SeccompStrict || sm == SeccompFiltering
}

// String returns a human-readable representation
func (sm SeccompMode) String() string {
	return string(sm)
}

// readFileSeccomp reads a file (internal helper for seccomp package)
func readFileSeccomp(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
