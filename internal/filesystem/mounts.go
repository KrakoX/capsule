package filesystem

import (
	"os"
	"strings"
)

// MountRisk represents a potentially dangerous mount point
type MountRisk struct {
	Source string
	Target string
	FSType string
	Risk   string // "CRITICAL", "HIGH", "MEDIUM"
	Reason string
}

// AnalyzeMounts parses /proc/mounts and categorizes mount points by risk
func AnalyzeMounts() []MountRisk {
	mounts := readFile("/proc/mounts")
	if mounts == "" {
		return []MountRisk{}
	}

	var risks []MountRisk

	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		source := fields[0]
		target := fields[1]
		fstype := fields[2]

		// Categorize by risk level
		if risk := assessMountRisk(source, target, fstype); risk != nil {
			risks = append(risks, *risk)
		}
	}

	return risks
}

// assessMountRisk evaluates the security risk of a mount point
func assessMountRisk(source, target, fstype string) *MountRisk {
	if strings.Contains(target, "docker.sock") {
		return &MountRisk{source, target, fstype, "CRITICAL", "docker socket - container escape"}
	}
	if strings.Contains(target, "containerd.sock") {
		return &MountRisk{source, target, fstype, "CRITICAL", "containerd socket - container escape"}
	}
	if strings.HasPrefix(target, "/host/") {
		return &MountRisk{source, target, fstype, "HIGH", "host filesystem access"}
	}
	if isDangerousDeviceMount(source, target, fstype) {
		return &MountRisk{source, target, fstype, "HIGH", "device node access"}
	}
	if isKernelInterfaceMount(target, fstype) {
		return &MountRisk{source, target, fstype, "HIGH", "kernel interface access"}
	}
	if fstype == "tmpfs" && (strings.Contains(target, "/dev") || strings.Contains(target, "/run")) {
		return &MountRisk{source, target, fstype, "MEDIUM", "privileged tmpfs mount"}
	}
	if strings.Contains(target, "cgroup") && !strings.Contains(target, "ro,") {
		return &MountRisk{source, target, fstype, "MEDIUM", "writable cgroup"}
	}
	return nil
}

// isDangerousDeviceMount returns true when a raw device node is bind-mounted
// into the container. Requires both source and target under /dev/ to avoid
// false positives from Docker using block devices as backing for bind mounts.
func isDangerousDeviceMount(source, target, fstype string) bool {
	if !strings.HasPrefix(source, "/dev/") || !strings.HasPrefix(target, "/dev/") {
		return false
	}
	if fstype == "tmpfs" || fstype == "devpts" {
		return false
	}
	for _, safe := range []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"} {
		if strings.Contains(target, safe) {
			return false
		}
	}
	return true
}

// isKernelInterfaceMount returns true when a /proc or /sys subpath is mounted
// into the container, excluding read-only informational paths.
func isKernelInterfaceMount(target, fstype string) bool {
	if !strings.HasPrefix(target, "/proc/") && !strings.HasPrefix(target, "/sys/") {
		return false
	}
	if strings.Contains(target, "/proc/acpi") || strings.Contains(target, "/proc/kcore") {
		return false
	}
	return fstype != "tmpfs"
}

// GetCriticalMounts returns only CRITICAL risk mounts
func GetCriticalMounts(risks []MountRisk) []MountRisk {
	var critical []MountRisk
	for _, r := range risks {
		if r.Risk == "CRITICAL" {
			critical = append(critical, r)
		}
	}
	return critical
}

// GetHighRiskMounts returns HIGH and CRITICAL risk mounts
func GetHighRiskMounts(risks []MountRisk) []MountRisk {
	var high []MountRisk
	for _, r := range risks {
		if r.Risk == "CRITICAL" || r.Risk == "HIGH" {
			high = append(high, r)
		}
	}
	return high
}

// readFile reads a file and returns its contents
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
