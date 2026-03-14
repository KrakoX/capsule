package security

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// UserNamespaceMapping represents a UID/GID mapping
type UserNamespaceMapping struct {
	ContainerID int
	HostID      int
	Range       int
}

// UserNamespaceInfo contains user namespace information
type UserNamespaceInfo struct {
	Enabled     bool
	UIDMappings []UserNamespaceMapping
	GIDMappings []UserNamespaceMapping
}

// GetUserNamespaceInfo reads and parses user namespace mappings
func GetUserNamespaceInfo() UserNamespaceInfo {
	info := UserNamespaceInfo{}

	// Read UID mappings
	info.UIDMappings = parseNamespaceMap("/proc/self/uid_map")

	// Read GID mappings
	info.GIDMappings = parseNamespaceMap("/proc/self/gid_map")

	// User namespace is enabled only when mappings differ from the identity
	// mapping (0 0 4294967295), which the kernel writes even without a user ns.
	info.Enabled = isUserNamespaceActive()

	return info
}

// parseNamespaceMap parses uid_map or gid_map file
func parseNamespaceMap(path string) []UserNamespaceMapping {
	data, err := os.ReadFile(path)
	if err != nil {
		return []UserNamespaceMapping{}
	}

	var mappings []UserNamespaceMapping

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		containerID, _ := strconv.Atoi(fields[0])
		hostID, _ := strconv.Atoi(fields[1])
		rangeSize, _ := strconv.Atoi(fields[2])

		mappings = append(mappings, UserNamespaceMapping{
			ContainerID: containerID,
			HostID:      hostID,
			Range:       rangeSize,
		})
	}

	return mappings
}

// String formats a mapping for display
func (m UserNamespaceMapping) String() string {
	return fmt.Sprintf("Container %d → Host %d (range: %d)", m.ContainerID, m.HostID, m.Range)
}
