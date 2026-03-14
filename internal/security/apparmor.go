package security

import (
	"os"
	"strings"
)

// GetAppArmorProfile reads the AppArmor profile from /proc/self/attr/current
func GetAppArmorProfile() string {
	data, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		return "unknown"
	}

	profile := strings.TrimSpace(string(data))

	// Handle common cases
	if profile == "" {
		return "none"
	}

	// Remove null terminators
	profile = strings.TrimRight(profile, "\x00")

	return profile
}

// IsAppArmorEnforced returns true if AppArmor is actively enforcing
func IsAppArmorEnforced(profile string) bool {
	// "unconfined" means no AppArmor restrictions
	// "none" or "unknown" means AppArmor not available
	return profile != "unconfined" && profile != "none" && profile != "unknown" && profile != ""
}
