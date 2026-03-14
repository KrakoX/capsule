package reporter

import (
	"encoding/json"
	"github.com/KrakoX/capsule/internal/filesystem"
	"github.com/KrakoX/capsule/internal/kubernetes"
	"github.com/KrakoX/capsule/internal/network"
	"github.com/KrakoX/capsule/internal/process"
	"github.com/KrakoX/capsule/internal/runtime"
	"github.com/KrakoX/capsule/internal/security"
)

// Report contains all security findings
type Report struct {
	Runtime    runtime.Runtime     `json:"runtime"`
	Security   SecurityReport      `json:"security"`
	Kubernetes *KubernetesReport   `json:"kubernetes,omitempty"`
	Filesystem FilesystemReport    `json:"filesystem"`
	Network    network.NetworkInfo `json:"network"`
	Process    process.ProcessInfo `json:"process"`
}

// SecurityReport combines security profile information
type SecurityReport struct {
	Capabilities security.CapabilitySet `json:"capabilities"`
	Namespaces   security.NamespaceInfo `json:"namespaces"`
	Seccomp      string                 `json:"seccomp"`
	AppArmor     string                 `json:"apparmor"`
}

// KubernetesReport contains Kubernetes-specific findings
type KubernetesReport struct {
	ServiceAccount  *kubernetes.ServiceAccount `json:"service_account,omitempty"`
	SecurityContext kubernetes.SecurityContext `json:"security_context"`
	HostAccess      kubernetes.HostAccess      `json:"host_access"`
}

// FilesystemReport contains filesystem analysis results
type FilesystemReport struct {
	DangerousMounts     []filesystem.MountRisk         `json:"dangerous_mounts"`
	SUIDBinaries        []filesystem.SUIDBinary        `json:"suid_binaries"`
	WritableDirectories []filesystem.WritableDirectory `json:"writable_directories"`
}

// ToJSON converts the report to JSON
func (r *Report) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
