package runtime

import (
	"os"
	"strings"
)

// Runtime represents the detected container runtime
type Runtime struct {
	Name         string // "containerd", "docker", "cri-o", "podman", "unknown"
	Variant      string // "k3s", "rke2", "microk8s", "" (empty for standard)
	DetectionVia string // "mountinfo", "cgroup", "fallback"
}

// Detect identifies the container runtime using signature-first detection
// This approach fixes the K3s misidentification bug by checking runtime
// signatures before checking filesystem paths
func Detect() Runtime {
	// Primary detection: Check /proc/1/mountinfo for runtime signatures
	mountInfo := readFile("/proc/1/mountinfo")
	if mountInfo != "" {
		if runtime := detectFromMountInfo(mountInfo); runtime.Name != "unknown" {
			return runtime
		}
	}

	// Fallback: Check /proc/1/cgroup
	cgroup := readFile("/proc/1/cgroup")
	if cgroup != "" {
		if runtime := detectFromCgroup(cgroup); runtime.Name != "unknown" {
			return runtime
		}
	}

	return Runtime{Name: "unknown", DetectionVia: "none"}
}

// detectFromMountInfo uses mount signatures for runtime detection
// SIGNATURE-FIRST approach: Check containerd signatures before paths
func detectFromMountInfo(mountInfo string) Runtime {
	// 1. Containerd signature detection (fixes K3s bug)
	// Check for io.containerd.grpc or io.containerd.snapshotter FIRST
	if strings.Contains(mountInfo, "io.containerd.grpc") ||
		strings.Contains(mountInfo, "io.containerd.snapshotter") ||
		strings.Contains(mountInfo, "containerd.sock") {

		// Identify specific Kubernetes distributions
		if strings.Contains(mountInfo, "/var/lib/rancher/k3s/") {
			return Runtime{
				Name:         "containerd",
				Variant:      "k3s",
				DetectionVia: "mountinfo",
			}
		}

		if strings.Contains(mountInfo, "/var/lib/rancher/rke2/") {
			return Runtime{
				Name:         "containerd",
				Variant:      "rke2",
				DetectionVia: "mountinfo",
			}
		}

		if strings.Contains(mountInfo, "/var/snap/microk8s/") {
			return Runtime{
				Name:         "containerd",
				Variant:      "microk8s",
				DetectionVia: "mountinfo",
			}
		}

		// Standard containerd (EKS, vanilla K8s, etc.)
		if strings.Contains(mountInfo, "/var/lib/containerd/") {
			return Runtime{
				Name:         "containerd",
				Variant:      "",
				DetectionVia: "mountinfo",
			}
		}

		// Generic containerd (signature found but no specific path)
		return Runtime{
			Name:         "containerd",
			Variant:      "",
			DetectionVia: "mountinfo",
		}
	}

	// 2. Docker detection
	if strings.Contains(mountInfo, "/var/lib/docker/") {
		return Runtime{
			Name:         "docker",
			Variant:      "",
			DetectionVia: "mountinfo",
		}
	}

	// 3. CRI-O detection
	if strings.Contains(mountInfo, "/var/lib/containers/storage/overlay") {
		return Runtime{
			Name:         "cri-o",
			Variant:      "",
			DetectionVia: "mountinfo",
		}
	}

	// 4. Podman detection
	if strings.Contains(mountInfo, ".local/share/containers/storage") {
		return Runtime{
			Name:         "podman",
			Variant:      "",
			DetectionVia: "mountinfo",
		}
	}

	return Runtime{Name: "unknown"}
}

// detectFromCgroup uses cgroup information as fallback detection
func detectFromCgroup(cgroup string) Runtime {
	// Check containerd patterns BEFORE docker to avoid false positives
	if strings.Contains(cgroup, "containerd") ||
		strings.Contains(cgroup, "k3s") ||
		strings.Contains(cgroup, "rke2") {
		return Runtime{
			Name:         "containerd",
			Variant:      "",
			DetectionVia: "cgroup",
		}
	}

	// Docker patterns
	if strings.Contains(cgroup, "/docker/") {
		return Runtime{
			Name:         "docker",
			Variant:      "",
			DetectionVia: "cgroup",
		}
	}

	// CRI-O patterns
	if strings.Contains(cgroup, "crio") {
		return Runtime{
			Name:         "cri-o",
			Variant:      "",
			DetectionVia: "cgroup",
		}
	}

	// Podman patterns
	if strings.Contains(cgroup, "podman") {
		return Runtime{
			Name:         "podman",
			Variant:      "",
			DetectionVia: "cgroup",
		}
	}

	return Runtime{Name: "unknown"}
}

// readFile reads a file and returns its contents, or empty string on error
func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// String returns a human-readable representation of the runtime
func (r Runtime) String() string {
	if r.Variant != "" {
		return r.Name + " (" + r.Variant + ")"
	}
	return r.Name
}
