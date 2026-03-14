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
	// CRITICAL: Docker socket (container escape)
	if strings.Contains(target, "docker.sock") {
		return &MountRisk{source, target, fstype, "CRITICAL", "docker socket - container escape"}
	}

	// CRITICAL: containerd socket
	if strings.Contains(target, "containerd.sock") {
		return &MountRisk{source, target, fstype, "CRITICAL", "containerd socket - container escape"}
	}

	// HIGH: Host filesystem paths
	if strings.HasPrefix(target, "/host") && target != "/host" {
		return &MountRisk{source, target, fstype, "HIGH", "host filesystem access"}
	}

	// HIGH: Raw device node bind-mounted into container.
	// Require BOTH source and target to be under /dev/ — Docker routinely
	// uses block devices (e.g. /dev/vdb1) as the backing store for bind-mounted
	// files like /etc/resolv.conf, which is NOT a dangerous device exposure.
	if strings.HasPrefix(source, "/dev/") &&
		strings.HasPrefix(target, "/dev/") &&
		fstype != "tmpfs" && fstype != "devpts" {
		if !strings.Contains(target, "/dev/null") &&
			!strings.Contains(target, "/dev/zero") &&
			!strings.Contains(target, "/dev/random") &&
			!strings.Contains(target, "/dev/urandom") {
			return &MountRisk{source, target, fstype, "HIGH", "device node access"}
		}
	}

	// HIGH: Kernel interfaces with write access
	if (strings.HasPrefix(target, "/proc/") || strings.HasPrefix(target, "/sys/")) &&
		!strings.Contains(target, "/proc/acpi") &&
		!strings.Contains(target, "/proc/kcore") &&
		fstype != "tmpfs" {
		return &MountRisk{source, target, fstype, "HIGH", "kernel interface access"}
	}

	// MEDIUM: tmpfs in privileged locations
	if fstype == "tmpfs" && (strings.Contains(target, "/dev") || strings.Contains(target, "/run")) {
		return &MountRisk{source, target, fstype, "MEDIUM", "privileged tmpfs mount"}
	}

	// MEDIUM: Writable cgroup
	if strings.Contains(target, "cgroup") && !strings.Contains(target, "ro,") {
		return &MountRisk{source, target, fstype, "MEDIUM", "writable cgroup"}
	}

	return nil
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
