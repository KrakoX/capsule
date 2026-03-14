package filesystem

import (
	"os"
	"path/filepath"
	"syscall"
)

// SUIDBinary represents a SUID binary with security implications
type SUIDBinary struct {
	Path       string
	Name       string
	Dangerous  bool   // Known dangerous SUID binary
	Reason     string // Why it's dangerous
}

var dangerousSUIDBinaries = map[string]string{
	"sudo":   "privilege escalation",
	"su":     "privilege escalation",
	"passwd": "password modification",
	"mount":  "filesystem manipulation",
	"umount": "filesystem manipulation",
	"docker": "container escape",
	"kubectl": "cluster control",
	"find":   "file system traversal + command execution",
	"vim":    "command execution via :!",
	"nano":   "command execution",
	"python": "command execution",
	"perl":   "command execution",
	"ruby":   "command execution",
	"bash":   "command execution",
	"sh":     "command execution",
}

// FindSUIDBinaries searches common paths for SUID binaries.
// Deduplicates by inode so that symlinked directories (e.g. /bin → /usr/bin
// on modern distros) do not produce duplicate entries.
func FindSUIDBinaries() []SUIDBinary {
	searchPaths := []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin"}
	var suidBinaries []SUIDBinary
	seen := make(map[uint64]bool) // inode → already reported

	for _, searchPath := range searchPaths {
		entries, err := os.ReadDir(searchPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			fullPath := filepath.Join(searchPath, entry.Name())
			info, err := os.Stat(fullPath)
			if err != nil {
				continue
			}

			// Deduplicate via inode (handles /bin → /usr/bin symlinks)
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if seen[stat.Ino] {
					continue
				}
				seen[stat.Ino] = true
			}

			// Check if SUID bit is set
			if info.Mode()&os.ModeSetuid != 0 {
				binary := SUIDBinary{
					Path: fullPath,
					Name: entry.Name(),
				}

				if reason, isDangerous := dangerousSUIDBinaries[entry.Name()]; isDangerous {
					binary.Dangerous = true
					binary.Reason = reason
				}

				suidBinaries = append(suidBinaries, binary)
			}
		}
	}

	return suidBinaries
}

// GetDangerousSUIDBinaries returns only dangerous SUID binaries
func GetDangerousSUIDBinaries(binaries []SUIDBinary) []SUIDBinary {
	var dangerous []SUIDBinary
	for _, b := range binaries {
		if b.Dangerous {
			dangerous = append(dangerous, b)
		}
	}
	return dangerous
}

// HasDangerousSUID checks if any dangerous SUID binaries exist
func HasDangerousSUID(binaries []SUIDBinary) bool {
	for _, b := range binaries {
		if b.Dangerous {
			return true
		}
	}
	return false
}
