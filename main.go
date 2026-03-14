package main

import (
	"github.com/KrakoX/capsule/internal/colors"
	"github.com/KrakoX/capsule/internal/filesystem"
	"github.com/KrakoX/capsule/internal/kubernetes"
	"github.com/KrakoX/capsule/internal/network"
	"github.com/KrakoX/capsule/internal/process"
	"github.com/KrakoX/capsule/internal/reporter"
	"github.com/KrakoX/capsule/internal/runtime"
	"github.com/KrakoX/capsule/internal/security"
	syscalltest "github.com/KrakoX/capsule/internal/syscall"
	"flag"
	"fmt"
	"os"
	"strings"
)

var version = "dev" // overridden at build time via -ldflags "-X main.version=..."

var (
	formatFlag   string
	outputFlag   string
	quietFlag    bool
	riskOnlyFlag bool
	versionFlag  bool
)

func init() {
	flag.StringVar(&formatFlag, "format", "text", "Output format: text, json")
	flag.StringVar(&outputFlag, "output", "", "Output file (default: stdout)")
	flag.BoolVar(&quietFlag, "quiet", false, "Suppress warnings, only show findings")
	flag.BoolVar(&riskOnlyFlag, "risk-only", false, "Only show HIGH and CRITICAL findings")
	flag.BoolVar(&versionFlag, "version", false, "Print version and exit")
}

func main() {
	flag.Parse()

	if versionFlag {
		fmt.Printf("capsule version %s\n", version)
		os.Exit(0)
	}

	// Collect all findings
	rt := runtime.Detect()
	caps := security.GetCapabilities()
	namespaces := security.GetNamespaces()
	userNS := security.GetUserNamespaceInfo()
	seccomp := security.GetSeccompMode()
	apparmor := security.GetAppArmorProfile()
	syscallTests := syscalltest.TestDangerousSyscalls()

	isK8s := kubernetes.IsK8sEnvironment()
	var sa *kubernetes.ServiceAccount
	var secCtx kubernetes.SecurityContext
	var hostAccess kubernetes.HostAccess
	if isK8s {
		sa = kubernetes.GetServiceAccount()
		secCtx = kubernetes.GetSecurityContext()
		hostAccess = kubernetes.DetectHostAccess()
	}

	mounts := filesystem.AnalyzeMounts()
	suidBinaries := filesystem.FindSUIDBinaries()
	writableDirs := filesystem.CheckWritableDirectories()
	dockerSockets := filesystem.FindDockerSockets()
	netInfo := network.GetNetworkInfo()
	procInfo := process.GetProcessInfo()

	// JSON output
	if formatFlag == "json" {
		report := reporter.Report{
			Runtime: rt,
			Security: reporter.SecurityReport{
				Capabilities: caps,
				Namespaces:   namespaces,
				Seccomp:      string(seccomp),
				AppArmor:     apparmor,
			},
			Filesystem: reporter.FilesystemReport{
				DangerousMounts:     mounts,
				SUIDBinaries:        suidBinaries,
				WritableDirectories: writableDirs,
			},
			Network: netInfo,
			Process: procInfo,
		}

		if isK8s {
			report.Kubernetes = &reporter.KubernetesReport{
				ServiceAccount:  sa,
				SecurityContext: secCtx,
				HostAccess:      hostAccess,
			}
		}

		jsonOutput, err := report.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating JSON: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(jsonOutput)
		return
	}

	// Text output with colors
	printHeader("CONTAINER SECURITY ASSESSMENT")
	fmt.Printf("Container Inspector v%s\n\n", version)

	// === CONTAINER RUNTIME ===
	printHeader("CONTAINER RUNTIME")
	fmt.Printf("Runtime:          %s\n", colors.Info(rt.String()))
	fmt.Printf("Detection Method: %s\n", rt.DetectionVia)
	if rt.Variant != "" {
		fmt.Printf("Distribution:     %s\n", colors.Info(rt.Variant))
	}
	fmt.Println()

	// === SECURITY PROFILE ===
	printHeader("SECURITY PROFILE")

	// Capabilities
	fmt.Println(colors.Header("Capabilities:"))
	if len(caps.Effective) == 0 {
		fmt.Printf("  Effective:   %s\n", colors.Good("none (restricted)"))
	} else {
		fmt.Printf("  Effective:   %s\n", formatCapList(caps.Effective))
		if caps.HasDangerousCapability() {
			fmt.Printf("  %s Dangerous capabilities present:\n", colors.High("[HIGH]"))
			for _, cap := range caps.Effective {
				if isDangerousCap(cap) {
					fmt.Printf("    - %s\n", colors.Warning(cap))
				}
			}
		}
	}
	fmt.Printf("  Bounding:    %d capabilities\n", len(caps.Bounding))

	if caps.NoNewPrivs {
		fmt.Printf("  NoNewPrivs:  %s\n", colors.Good("true"))
	} else {
		fmt.Printf("  NoNewPrivs:  %s (can gain privileges via setuid)\n", colors.Warning("false"))
	}

	riskColor := getRiskColor(caps.RiskLevel)
	fmt.Printf("  Risk Level:  %s\n", riskColor(caps.RiskLevel))
	fmt.Println()

	// Namespaces
	fmt.Println(colors.Header("Namespaces:"))
	fmt.Printf("  PID:    %s   Net:   %s   Mount: %s\n",
		formatBool(namespaces.PID), formatBool(namespaces.Net), formatBool(namespaces.Mount))
	fmt.Printf("  UTS:    %s   IPC:   %s   User:  %s\n",
		formatBool(namespaces.UTS), formatBool(namespaces.IPC), formatBool(namespaces.User))

	isolationColor := getIsolationColor(namespaces.IsolationLevel())
	fmt.Printf("  Isolation:  %s\n", isolationColor(namespaces.IsolationLevel()))

	// User namespace mappings
	if userNS.Enabled {
		fmt.Printf("  %s User namespace mappings detected:\n", colors.Info("[INFO]"))
		if len(userNS.UIDMappings) > 0 {
			fmt.Println("    UID mappings:")
			for _, m := range userNS.UIDMappings {
				fmt.Printf("      %s\n", m.String())
			}
		}
		if len(userNS.GIDMappings) > 0 {
			fmt.Println("    GID mappings:")
			for _, m := range userNS.GIDMappings {
				fmt.Printf("      %s\n", m.String())
			}
		}
	}
	fmt.Println()

	// Security profiles
	fmt.Println(colors.Header("Security Profiles:"))
	if seccomp == security.SeccompDisabled {
		fmt.Printf("  Seccomp:  %s (all syscalls allowed)\n", colors.High(string(seccomp)))
	} else {
		fmt.Printf("  Seccomp:  %s\n", colors.Good(string(seccomp)))
	}

	if apparmor == "unconfined" {
		fmt.Printf("  AppArmor: %s (no MAC enforcement)\n", colors.Warning(apparmor))
	} else if apparmor == "unknown" || apparmor == "none" {
		fmt.Printf("  AppArmor: %s\n", colors.GrayText(apparmor))
	} else {
		fmt.Printf("  AppArmor: %s\n", colors.Good(apparmor))
	}
	fmt.Println()

	// Syscall restrictions
	fmt.Println(colors.Header("Syscall Restrictions:"))
	allowedSyscalls := syscalltest.GetAllowed(syscallTests)
	blockedSyscalls := syscalltest.GetBlocked(syscallTests)

	if len(allowedSyscalls) == 0 {
		fmt.Printf("  %s All dangerous syscalls blocked\n", colors.Good("[OK]"))
	} else {
		fmt.Printf("  %s %d dangerous syscalls allowed:\n", colors.High("[HIGH]"), len(allowedSyscalls))
		for _, test := range allowedSyscalls {
			fmt.Printf("    - %s\n", colors.Warning(test.Name))
		}
	}

	if len(blockedSyscalls) > 0 && !quietFlag {
		fmt.Printf("  Blocked: %d/%d\n", len(blockedSyscalls), len(syscallTests))
	}
	fmt.Println()

	// === KUBERNETES CONTEXT ===
	if isK8s {
		printHeader("KUBERNETES CONTEXT")

		// Service account
		if sa != nil {
			fmt.Println(colors.Header("Service Account:"))
			if sa.IsDefault {
				fmt.Printf("  Name:       %s (using default SA)\n", colors.Warning(sa.Name))
			} else {
				fmt.Printf("  Name:       %s\n", colors.Good(sa.Name))
			}
			fmt.Printf("  Namespace:  %s\n", sa.Namespace)
			fmt.Printf("  Token:      %s\n", formatBool(sa.Token))
			fmt.Printf("  CA Cert:    %s\n", formatBool(sa.CACert))
			fmt.Println()
		}

		// Security context
		fmt.Println(colors.Header("Pod Security Context:"))
		if secCtx.RunAsUser == 0 {
			fmt.Printf("  runAsUser:              %s (root)\n", colors.High("0"))
		} else {
			fmt.Printf("  runAsUser:              %d\n", secCtx.RunAsUser)
		}
		fmt.Printf("  runAsGroup:             %d\n", secCtx.RunAsGroup)
		fmt.Printf("  runAsNonRoot:           %s\n", formatBool(secCtx.RunAsNonRoot))
		fmt.Printf("  readOnlyRootFilesystem: %s\n", formatBool(secCtx.ReadOnlyRoot))
		fmt.Println()

		// Host access
		fmt.Println(colors.Header("Host Access:"))
		if hostAccess.HostNetwork {
			fmt.Printf("  hostNetwork: %s HIGH RISK - container shares host network\n", colors.Critical("true"))
		} else {
			fmt.Printf("  hostNetwork: %s\n", colors.Good("false"))
		}

		if hostAccess.HostPID {
			fmt.Printf("  hostPID:     %s HIGH RISK - can see host processes\n", colors.Critical("true"))
		} else {
			fmt.Printf("  hostPID:     %s\n", colors.Good("false"))
		}

		if hostAccess.HostIPC {
			fmt.Printf("  hostIPC:     %s HIGH RISK - shared IPC namespace\n", colors.Critical("true"))
		} else {
			fmt.Printf("  hostIPC:     %s\n", colors.Good("false"))
		}
		fmt.Println()
	}

	// === FILESYSTEM ANALYSIS ===
	printHeader("FILESYSTEM ANALYSIS")

	// Docker socket detection
	if len(dockerSockets) > 0 {
		validSockets := filesystem.HasValidDockerSocket(dockerSockets)
		if validSockets {
			fmt.Printf("%s CONTAINER ESCAPE VECTOR DETECTED\n", colors.Critical("[CRITICAL]"))
			fmt.Println("Valid Docker Socket(s) found:")
			for _, sock := range dockerSockets {
				if sock.Valid {
					fmt.Printf("  - %s %s\n", colors.Critical(sock.Path), colors.Critical("(escape possible)"))
				}
			}
			fmt.Println()
		}
	}

	// Dangerous mounts
	criticalMounts := filesystem.GetCriticalMounts(mounts)
	highRiskMounts := filesystem.GetHighRiskMounts(mounts)

	if len(criticalMounts) > 0 {
		fmt.Printf("%s Critical Mounts (escape vectors):\n", colors.Critical("[CRITICAL]"))
		for _, m := range criticalMounts {
			fmt.Printf("  %s -> %s\n", m.Source, m.Target)
			fmt.Printf("    Reason: %s\n", colors.Critical(m.Reason))
		}
		fmt.Println()
	}

	if len(highRiskMounts) > len(criticalMounts) {
		fmt.Printf("%s High Risk Mounts:\n", colors.High("[HIGH]"))
		count := 0
		for _, m := range highRiskMounts {
			if m.Risk == "HIGH" {
				fmt.Printf("  %s -> %s (%s)\n", m.Source, m.Target, m.Reason)
				count++
				if count >= 5 && !quietFlag {
					remaining := len(highRiskMounts) - len(criticalMounts) - 5
					if remaining > 0 {
						fmt.Printf("  ... and %d more\n", remaining)
						break
					}
				}
			}
		}
		fmt.Println()
	}

	if len(criticalMounts) == 0 && len(highRiskMounts) == 0 {
		fmt.Printf("%s No dangerous mounts detected\n\n", colors.Good("[OK]"))
	}

	// SUID binaries
	dangerousSUID := filesystem.GetDangerousSUIDBinaries(suidBinaries)

	fmt.Printf("SUID Binaries: %d found", len(suidBinaries))
	if len(suidBinaries) > 15 {
		fmt.Printf(" %s\n", colors.Warning("(many)"))
	} else {
		fmt.Println()
	}

	if len(dangerousSUID) > 0 {
		fmt.Printf("%s Dangerous SUID Binaries:\n", colors.High("[HIGH]"))

		// Deduplicate by name - prefer shorter paths
		seen := make(map[string]filesystem.SUIDBinary)
		for _, b := range dangerousSUID {
			if existing, exists := seen[b.Name]; !exists || len(b.Path) < len(existing.Path) {
				seen[b.Name] = b
			}
		}

		for _, b := range seen {
			fmt.Printf("  %s (%s)\n", colors.Warning(b.Path), b.Reason)
		}
	}
	fmt.Println()

	// Writable directories
	sensitiveDirs := filesystem.GetSensitiveWritable(writableDirs)

	if len(sensitiveDirs) > 0 {
		fmt.Printf("%s Sensitive Writable Directories:\n", colors.Medium("[MEDIUM]"))
		for _, d := range sensitiveDirs {
			fmt.Printf("  %s (%s)\n", colors.Warning(d.Path), d.Reason)
		}
		fmt.Println()
	}

	// Development tools
	devTools := filesystem.FindDevelopmentTools()
	if len(devTools) > 0 {
		hasOffensive := filesystem.HasOffensiveTools(devTools)
		if hasOffensive {
			fmt.Printf("%s Development Tools (attack vectors):\n", colors.Medium("[MEDIUM]"))
		} else {
			fmt.Println("Development Tools:")
		}

		categories := filesystem.GetToolsByCategory(devTools)
		for category, tools := range categories {
			if len(tools) > 0 {
				fmt.Printf("  %s: ", category)
				names := []string{}
				for _, t := range tools {
					names = append(names, t.Name)
				}
				if hasOffensive {
					fmt.Printf("%s\n", colors.Warning(strings.Join(names, ", ")))
				} else {
					fmt.Printf("%s\n", strings.Join(names, ", "))
				}
			}
		}
		fmt.Println()
	}

	// === NETWORK ANALYSIS ===
	printHeader("NETWORK ANALYSIS")

	fmt.Printf("Interfaces: %d found", len(netInfo.Interfaces))
	if len(netInfo.Interfaces) > 0 {
		fmt.Printf(" (%s)\n", strings.Join(netInfo.Interfaces, ", "))
	} else {
		fmt.Println()
	}

	if netInfo.HostNetwork {
		fmt.Printf("Isolation:  %s\n", colors.High(netInfo.IsolationLevel))
	} else {
		isolationColor := getIsolationColor(netInfo.IsolationLevel)
		fmt.Printf("Isolation:  %s\n", isolationColor(netInfo.IsolationLevel))
	}

	fmt.Printf("DNS Type:   %s\n", netInfo.DNS.DNSType)
	if len(netInfo.DNS.Nameservers) > 0 && !quietFlag {
		fmt.Printf("Nameserver: %s\n", strings.Join(netInfo.DNS.Nameservers, ", "))
	}
	fmt.Println()

	// === PROCESS ANALYSIS ===
	printHeader("PROCESS ANALYSIS")

	fmt.Printf("PID 1:     %s\n", procInfo.PID1Command)
	if procInfo.HasShellAccess {
		fmt.Printf("           %s Shell at PID 1 (interactive access)\n", colors.Medium("[MEDIUM]"))
	}

	if !quietFlag {
		fmt.Printf("Current:   %s\n", procInfo.CurrentProcess)
	}

	assessment := procInfo.GetSecurityAssessment()
	assessColor := getRiskColor(assessment)
	fmt.Printf("Security:  %s\n", assessColor(assessment))
	fmt.Println()

}

// Helper functions

func printHeader(title string) {
	fmt.Printf("%s\n", colors.Header("=== "+title+" ==="))
}

func formatCapList(caps []string) string {
	if len(caps) == 0 {
		return "none"
	}
	if len(caps) <= 3 {
		return strings.Join(caps, ", ")
	}
	return fmt.Sprintf("%s, ... (%d total)", strings.Join(caps[:3], ", "), len(caps))
}

func formatBool(b bool) string {
	if b {
		return colors.Good("true")
	}
	return colors.GrayText("false")
}

func getRiskColor(risk string) func(string) string {
	switch risk {
	case "CRITICAL":
		return colors.Critical
	case "HIGH":
		return colors.High
	case "MEDIUM":
		return colors.Medium
	case "LOW":
		return colors.Low
	default:
		return colors.Info
	}
}

func getIsolationColor(isolation string) func(string) string {
	switch isolation {
	case "FULL", "FULL (no interfaces)":
		return colors.Good
	case "STRONG", "STRONG (single interface)":
		return colors.Good
	case "MODERATE":
		return colors.Warning
	case "WEAK", "NONE", "NONE (host network)":
		return colors.High
	default:
		return colors.Info
	}
}

func isDangerousCap(cap string) bool {
	dangerous := []string{"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "DAC_OVERRIDE", "DAC_READ_SEARCH"}
	for _, d := range dangerous {
		if strings.Contains(cap, d) {
			return true
		}
	}
	return false
}
