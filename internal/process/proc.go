package process

import (
	"fmt"
	"os"
	"strings"
)

// ProcessInfo represents security-relevant process information
type ProcessInfo struct {
	PID1Command    string
	CurrentProcess string
	ParentProcess  string
	IsRootProcess  bool
	HasShellAccess bool
}

// GetProcessInfo analyzes running processes for security context
func GetProcessInfo() ProcessInfo {
	info := ProcessInfo{}

	// Get PID 1 (init process)
	info.PID1Command = getProcessCommand(1)

	// Get current process
	pid := os.Getpid()
	info.CurrentProcess = fmt.Sprintf("PID %d: %s", pid, getProcessCommand(pid))

	// Get parent process
	ppid := getParentPID(pid)
	if ppid > 0 {
		info.ParentProcess = fmt.Sprintf("PID %d: %s", ppid, getProcessCommand(ppid))
	}

	// Check if PID 1 is a shell (indicates potential shell access)
	info.HasShellAccess = isShellProcess(info.PID1Command)

	// Check if running as root
	info.IsRootProcess = (os.Getuid() == 0)

	return info
}

// getProcessCommand reads the command line for a given PID
func getProcessCommand(pid int) string {
	cmdlinePath := fmt.Sprintf("/proc/%d/cmdline", pid)
	data, err := os.ReadFile(cmdlinePath)
	if err != nil {
		return "unknown"
	}

	// Replace null bytes with spaces
	cmdline := strings.ReplaceAll(string(data), "\x00", " ")
	cmdline = strings.TrimSpace(cmdline)

	if cmdline == "" {
		return "unknown"
	}

	return cmdline
}

// getParentPID reads the parent PID from /proc/{pid}/stat
func getParentPID(pid int) int {
	statPath := fmt.Sprintf("/proc/%d/stat", pid)
	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	// Parse stat file: PID (name) state PPID ...
	fields := strings.Fields(string(data))
	if len(fields) < 4 {
		return 0
	}

	// PPID is the 4th field
	var ppid int
	fmt.Sscanf(fields[3], "%d", &ppid)
	return ppid
}

// isShellProcess checks if a command is a shell
func isShellProcess(cmd string) bool {
	cmd = strings.ToLower(cmd)
	return strings.Contains(cmd, "bash") ||
		strings.Contains(cmd, "/sh") ||
		strings.Contains(cmd, "zsh") ||
		strings.Contains(cmd, "fish")
}

// GetSecurityAssessment provides a security assessment of process state
func (pi ProcessInfo) GetSecurityAssessment() string {
	risks := []string{}

	if pi.HasShellAccess {
		risks = append(risks, "Shell at PID 1 (interactive access)")
	}

	if pi.IsRootProcess {
		risks = append(risks, "Running as root")
	}

	if len(risks) == 0 {
		return "LOW"
	} else if len(risks) == 1 {
		return "MEDIUM"
	}

	return "HIGH"
}
