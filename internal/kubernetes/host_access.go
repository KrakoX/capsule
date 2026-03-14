package kubernetes

import (
	"os"
	"strings"
)

// HostAccess represents host namespace access configuration
type HostAccess struct {
	HostNetwork bool
	HostPID     bool
	HostIPC     bool
}

// DetectHostAccess checks which host namespaces are accessible
func DetectHostAccess() HostAccess {
	return HostAccess{
		HostNetwork: checkHostNetwork(),
		HostPID:     checkHostPID(),
		HostIPC:     checkHostIPC(),
	}
}

// checkHostNetwork detects if container uses host network namespace.
// docker0 and veth* interfaces only exist inside the host's network namespace —
// they are never visible from inside an isolated container.
func checkHostNetwork() bool {
	netDev := readFileStringHost("/proc/net/dev")
	for _, line := range strings.Split(netDev, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		iface := strings.TrimSpace(strings.Split(line, ":")[0])
		if iface == "docker0" || strings.HasPrefix(iface, "veth") {
			return true
		}
	}
	return false
}

// checkHostPID detects if container uses host PID namespace.
// Uses two complementary signals: PID 1 is a known host init process with
// more than 10 visible PIDs, or more than 100 visible PIDs regardless of name.
func checkHostPID() bool {
	pids := countPIDs()
	if pids > 100 {
		return true
	}
	if pids > 10 {
		cmdline := readFileStringHost("/proc/1/cmdline")
		cmdline = strings.ReplaceAll(cmdline, "\x00", " ")
		if strings.Contains(cmdline, "/sbin/init") ||
			strings.Contains(cmdline, "systemd") {
			return true
		}
	}
	return false
}

// checkHostIPC detects if container uses host IPC namespace.
// From inside a container we cannot reliably distinguish host IPC from
// container IPC using namespace inode comparison (both PID 1 and self are
// in the same namespace regardless). Default to false (isolated).
func checkHostIPC() bool {
	return false
}

// countPIDs counts the number of numeric entries in /proc.
func countPIDs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			name := e.Name()
			isNum := len(name) > 0
			for _, c := range name {
				if c < '0' || c > '9' {
					isNum = false
					break
				}
			}
			if isNum {
				count++
			}
		}
	}
	return count
}

func readFileStringHost(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
