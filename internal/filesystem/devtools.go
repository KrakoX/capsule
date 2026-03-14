package filesystem

import (
	"os/exec"
)

// DevTool represents a detected development tool
type DevTool struct {
	Name    string
	Path    string
	Version string
}

// FindDevelopmentTools searches for common development and attack tools
func FindDevelopmentTools() []DevTool {
	tools := []string{
		"python", "python3", "python2",
		"bash", "sh", "zsh",
		"perl",
		"ruby",
		"gcc", "cc",
		"curl", "wget",
		"nc", "netcat", "ncat",
		"socat",
		"git",
		"docker",
		"kubectl",
		"nmap",
	}

	var found []DevTool

	for _, tool := range tools {
		path, err := exec.LookPath(tool)
		if err == nil {
			// Tool exists - don't execute anything, just note it
			found = append(found, DevTool{
				Name:    tool,
				Path:    path,
				Version: "present",
			})
		}
	}

	return found
}

// GetToolsByCategory categorizes tools
func GetToolsByCategory(tools []DevTool) map[string][]DevTool {
	categories := make(map[string][]DevTool)

	for _, tool := range tools {
		switch tool.Name {
		case "python", "python2", "python3":
			categories["scripting"] = append(categories["scripting"], tool)
		case "bash", "sh", "zsh":
			categories["shells"] = append(categories["shells"], tool)
		case "perl", "ruby":
			categories["scripting"] = append(categories["scripting"], tool)
		case "gcc", "cc":
			categories["compilers"] = append(categories["compilers"], tool)
		case "curl", "wget":
			categories["network"] = append(categories["network"], tool)
		case "nc", "netcat", "ncat", "socat":
			categories["network"] = append(categories["network"], tool)
		case "git":
			categories["vcs"] = append(categories["vcs"], tool)
		case "docker", "kubectl":
			categories["containers"] = append(categories["containers"], tool)
		case "nmap":
			categories["security"] = append(categories["security"], tool)
		}
	}

	return categories
}

// HasOffensiveTools checks if any offensive/pivoting tools are present
func HasOffensiveTools(tools []DevTool) bool {
	offensive := []string{"python", "python3", "bash", "perl", "ruby", "nc", "netcat", "ncat", "socat", "curl", "wget"}

	for _, tool := range tools {
		for _, off := range offensive {
			if tool.Name == off {
				return true
			}
		}
	}

	return false
}
