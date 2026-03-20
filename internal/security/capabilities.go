package security

import (
	"os"
	"strconv"
	"strings"
)

// CapabilitySet represents Linux capability information
type CapabilitySet struct {
	Effective   []string
	Permitted   []string
	Inheritable []string
	Bounding    []string
	Ambient     []string
	NoNewPrivs  bool
	RiskLevel   string // "CRITICAL", "HIGH", "MEDIUM", "LOW"
}

// Capability name mapping (Linux kernel capability bits)
var capabilityNames = map[int]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

// severeCaps are non-default capabilities with documented container escape vectors
var severeCaps = map[string]bool{
	"CAP_SYS_ADMIN":  true, // CVE-2022-0492, CVE-2022-0185
	"CAP_SYS_PTRACE": true, // process injection, CVE-2019-5736 chain
	"CAP_SYS_MODULE": true, // kernel module load = arbitrary kernel code execution
	"CAP_SYS_RAWIO":  true, // /dev/mem physical memory R/W
	"CAP_BPF":        true, // CVE-2021-3490, CVE-2022-23222 (eBPF verifier bypass)
	"CAP_SYS_BOOT":   true, // kexec_load: replace running kernel
}

// notableCaps are non-default capabilities that are indirect attack enablers.
// Docker-default caps (DAC_OVERRIDE, DAC_READ_SEARCH, NET_RAW) are excluded
// to avoid noise on every default container.
var notableCaps = map[string]bool{
	"CAP_NET_ADMIN":          true, // iptables bypass, cluster lateral movement
	"CAP_SYSLOG":             true, // KASLR bypass via dmesg (kernel address leak)
	"CAP_PERFMON":            true, // LLC side-channel attacks, crypto key extraction
	"CAP_CHECKPOINT_RESTORE": true, // CRIU process injection
}

// GetCapabilities reads and parses capability information from /proc/self/status
func GetCapabilities() CapabilitySet {
	status := readFile("/proc/self/status")
	if status == "" {
		return CapabilitySet{}
	}

	caps := CapabilitySet{
		Effective:   parseCapabilityLine(status, "CapEff:"),
		Permitted:   parseCapabilityLine(status, "CapPrm:"),
		Inheritable: parseCapabilityLine(status, "CapInh:"),
		Bounding:    parseCapabilityLine(status, "CapBnd:"),
		Ambient:     parseCapabilityLine(status, "CapAmb:"),
		NoNewPrivs:  parseNoNewPrivs(status),
	}

	caps.RiskLevel = assessRisk(caps.Effective)

	return caps
}

// parseCapabilityLine extracts and decodes capability hex value from /proc/self/status
func parseCapabilityLine(status, prefix string) []string {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, prefix) {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return decodeCapabilities(parts[1])
			}
		}
	}
	return []string{}
}

// decodeCapabilities converts hex capability bitmask to capability names
func decodeCapabilities(hexStr string) []string {
	// Remove 0x prefix if present
	hexStr = strings.TrimPrefix(hexStr, "0x")

	// Parse hex string to uint64
	capBits, err := strconv.ParseUint(hexStr, 16, 64)
	if err != nil {
		return []string{}
	}

	var caps []string

	// Check each bit (Linux has 41 capabilities as of kernel 5.9+)
	for bit := 0; bit <= 40; bit++ {
		if capBits&(1<<uint(bit)) != 0 {
			if name, exists := capabilityNames[bit]; exists {
				caps = append(caps, name)
			}
		}
	}

	return caps
}

// parseNoNewPrivs extracts NoNewPrivs flag from /proc/self/status
func parseNoNewPrivs(status string) bool {
	for _, line := range strings.Split(status, "\n") {
		if strings.HasPrefix(line, "NoNewPrivs:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1] == "1"
			}
		}
	}
	return false
}

// assessRisk evaluates the security risk based on effective capabilities
func assessRisk(effectiveCaps []string) string {
	if len(effectiveCaps) == 0 {
		return "LOW"
	}
	severeCount, notableCount := 0, 0
	for _, cap := range effectiveCaps {
		switch {
		case severeCaps[cap]:
			severeCount++
		case notableCaps[cap]:
			notableCount++
		}
	}
	switch {
	case severeCount >= 2:
		return "CRITICAL"
	case severeCount == 1:
		return "HIGH"
	case notableCount > 0 || len(effectiveCaps) > 5:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func IsSevereCap(cap string) bool  { return severeCaps[cap] }
func IsNotableCap(cap string) bool { return notableCaps[cap] }

// readFile reads a file and returns its contents as a string
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
