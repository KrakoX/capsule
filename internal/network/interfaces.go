package network

import (
	"os"
	"strings"
)

// NetworkInfo represents network configuration and interfaces
type NetworkInfo struct {
	Interfaces   []string
	DNS          DNSConfig
	HostNetwork  bool
	IsolationLevel string
}

// DNSConfig represents DNS configuration
type DNSConfig struct {
	Nameservers []string
	SearchDomains []string
	DNSType     string // "cluster", "host", "custom"
}

// GetNetworkInfo analyzes network configuration
func GetNetworkInfo() NetworkInfo {
	info := NetworkInfo{}

	// Get network interfaces
	info.Interfaces = getInterfaces()

	// Determine if using host network
	info.HostNetwork = checkHostNetwork(info.Interfaces)

	// Get DNS configuration
	info.DNS = getDNSConfig()

	// Determine isolation level
	info.IsolationLevel = assessNetworkIsolation(info)

	return info
}

// getInterfaces parses /proc/net/dev for network interfaces
func getInterfaces() []string {
	netDev := readFile("/proc/net/dev")
	if netDev == "" {
		return []string{}
	}

	var interfaces []string

	for _, line := range strings.Split(netDev, "\n") {
		if strings.Contains(line, ":") &&
		   !strings.Contains(line, "Inter-") &&
		   !strings.Contains(line, "face") {

			iface := strings.TrimSpace(strings.Split(line, ":")[0])
			if iface != "lo" { // Skip loopback
				interfaces = append(interfaces, iface)
			}
		}
	}

	return interfaces
}

// checkHostNetwork returns true when host-network-namespace indicators are
// present. docker0 and veth* interfaces only exist inside the host's network
// namespace — they are never visible from inside an isolated container.
func checkHostNetwork(interfaces []string) bool {
	for _, iface := range interfaces {
		if iface == "docker0" || strings.HasPrefix(iface, "veth") {
			return true
		}
	}
	return false
}

// getDNSConfig reads and parses /etc/resolv.conf
func getDNSConfig() DNSConfig {
	resolvConf := readFile("/etc/resolv.conf")
	if resolvConf == "" {
		return DNSConfig{}
	}

	config := DNSConfig{}

	for _, line := range strings.Split(resolvConf, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "nameserver ") {
			ns := strings.TrimPrefix(line, "nameserver ")
			config.Nameservers = append(config.Nameservers, strings.TrimSpace(ns))
		}

		if strings.HasPrefix(line, "search ") {
			domains := strings.TrimPrefix(line, "search ")
			config.SearchDomains = strings.Fields(domains)
		}
	}

	// Determine DNS type
	resolvStr := string(resolvConf)
	if strings.Contains(resolvStr, "cluster.local") {
		config.DNSType = "kubernetes"
	} else if strings.Contains(resolvStr, "127.0.0.11") {
		config.DNSType = "docker"
	} else if len(config.Nameservers) > 0 {
		config.DNSType = "custom"
	} else {
		config.DNSType = "unknown"
	}

	return config
}

// assessNetworkIsolation determines network isolation level
func assessNetworkIsolation(info NetworkInfo) string {
	if info.HostNetwork {
		return "NONE (host network)"
	}

	if len(info.Interfaces) == 0 {
		return "FULL (no interfaces)"
	}

	if len(info.Interfaces) == 1 {
		return "STRONG (single interface)"
	}

	return "MODERATE"
}

// readFile reads a file and returns its contents
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}
