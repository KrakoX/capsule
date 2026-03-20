package security

import (
	"os"
	"strconv"
	"strings"
)

// NamespaceInfo represents namespace isolation information.
// true = isolated from host (own namespace), false = sharing host namespace.
type NamespaceInfo struct {
	PID   bool // isolated PID namespace
	Net   bool // isolated network namespace
	Mount bool // isolated mount namespace
	UTS   bool // isolated UTS (hostname) namespace
	IPC   bool // isolated IPC namespace
	User  bool // user namespace active
}

// GetNamespaces detects which namespaces are isolated from the host.
// From inside a container we cannot compare against the host's init namespace
// directly (the container's /proc only exposes the container's process tree).
// Instead we detect positive indicators of HOST namespace sharing.
func GetNamespaces() NamespaceInfo {
	return NamespaceInfo{
		PID:   !isHostPIDNamespace(),
		Net:   !isHostNetworkNamespace(),
		Mount: !isHostMountNamespace(),
		UTS:   !isHostUTSNamespace(),
		IPC:   !isHostIPCNamespace(),
		User:  isUserNamespaceActive(),
	}
}

// isHostPIDNamespace returns true if the container shares the host PID namespace
// (--pid=host / hostPID: true). Uses two complementary signals:
//  1. PID 1 is a known host init process (systemd, init) with more than ~10
//     visible PIDs — rules out single-process containers that happen to name
//     their entrypoint "init".
//  2. More than 100 visible PIDs regardless of PID 1 name, which covers busy
//     hosts where the init name is non-standard.
func isHostPIDNamespace() bool {
	pids := countVisiblePIDs()
	if pids > 100 {
		return true
	}
	if pids > 10 {
		comm := strings.TrimSpace(readFile("/proc/1/comm"))
		if comm == "systemd" || comm == "init" {
			return true
		}
	}
	return false
}

// isHostNetworkNamespace returns true if the container shares the host network
// namespace (--network=host / hostNetwork: true). Detected by host-side
// network infrastructure that only appears inside the host's network namespace.
func isHostNetworkNamespace() bool {
	netDev := readFile("/proc/net/dev")
	for _, line := range strings.Split(netDev, "\n") {
		if !strings.Contains(line, ":") {
			continue
		}
		iface := strings.TrimSpace(strings.Split(line, ":")[0])
		// docker0 and veth* only appear on the host side, never inside a container
		if iface == "docker0" || strings.HasPrefix(iface, "veth") {
			return true
		}
	}
	return false
}

// isHostMountNamespace returns true if the container shares the host mount
// namespace. This is rare and hard to detect; we default to isolated.
func isHostMountNamespace() bool {
	return false
}

// isHostUTSNamespace returns true if the container shares the host UTS
// namespace (hostname). Hard to detect reliably; default to isolated.
func isHostUTSNamespace() bool {
	return false
}

// isHostIPCNamespace returns true if the container shares the host IPC
// namespace. Hard to detect reliably; default to isolated.
func isHostIPCNamespace() bool {
	return false
}

// isUserNamespaceActive returns true when a real user namespace mapping is
// present (container UIDs differ from host UIDs). The identity mapping
// "0 0 4294967295" is written by the kernel even without a user namespace
// and is NOT considered an active user namespace.
func isUserNamespaceActive() bool {
	uidMap := strings.TrimSpace(readFile("/proc/self/uid_map"))
	if uidMap == "" {
		return false
	}
	fields := strings.Fields(uidMap)
	if len(fields) < 3 {
		return false
	}
	containerID, _ := strconv.Atoi(fields[0])
	hostID, _ := strconv.Atoi(fields[1])
	rangeSize, _ := strconv.Atoi(fields[2])

	// Identity mapping: container root == host root, full UID range → no user namespace
	if containerID == 0 && hostID == 0 && rangeSize >= 4294967294 {
		return false
	}
	return true
}

// countVisiblePIDs counts the number of numeric entries in /proc,
// which equals the number of processes visible in the current PID namespace.
func countVisiblePIDs() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			if _, err := strconv.Atoi(e.Name()); err == nil {
				count++
			}
		}
	}
	return count
}

// IsFullyIsolated returns true if all namespaces are isolated.
func (ni NamespaceInfo) IsFullyIsolated() bool {
	return ni.PID && ni.Net && ni.Mount && ni.UTS && ni.IPC && ni.User
}

// IsolationLevel returns a string describing the overall isolation level.
// Sharing the host network or PID namespace caps the result at MODERATE — both
// have documented host-escape consequences regardless of other namespace counts.
func (ni NamespaceInfo) IsolationLevel() string {
	isolated := 0
	for _, v := range []bool{ni.PID, ni.Net, ni.Mount, ni.UTS, ni.IPC, ni.User} {
		if v {
			isolated++
		}
	}
	highRiskShared := !ni.PID || !ni.Net
	switch {
	case isolated == 6:
		return "FULL"
	case isolated >= 4 && !highRiskShared:
		return "STRONG"
	case isolated >= 2:
		return "MODERATE"
	case isolated > 0:
		return "WEAK"
	default:
		return "NONE"
	}
}
