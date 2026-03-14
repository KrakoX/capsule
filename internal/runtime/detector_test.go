package runtime

import (
	"testing"
)

func TestDetectFromMountInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		mountInfo    string
		wantName     string
		wantVariant  string
		wantVia      string
	}{
		{
			name: "standard containerd (EKS)",
			mountInfo: `36 35 98:0 /mnt1 /mnt2 rw,noatime shared:1 - ext3 /dev/root rw,errors=continue
/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots`,
			wantName:    "containerd",
			wantVariant: "",
			wantVia:     "mountinfo",
		},
		{
			name: "k3s is NOT misidentified as docker",
			mountInfo: `36 35 98:0 /mnt1 /mnt2 rw shared:1 - ext3 /dev/root rw
/var/lib/rancher/k3s/agent/containerd/io.containerd.grpc.v1.cri/containers`,
			wantName:    "containerd",
			wantVariant: "k3s",
			wantVia:     "mountinfo",
		},
		{
			name: "rke2 detection",
			mountInfo: `/var/lib/rancher/rke2/agent/containerd/io.containerd.snapshotter.v1.overlayfs`,
			wantName:    "containerd",
			wantVariant: "rke2",
			wantVia:     "mountinfo",
		},
		{
			name: "microk8s detection",
			mountInfo: `/var/snap/microk8s/common/run/containerd.sock`,
			wantName:    "containerd",
			wantVariant: "microk8s",
			wantVia:     "mountinfo",
		},
		{
			name: "docker detection",
			mountInfo: `/var/lib/docker/overlay2/abc123/merged`,
			wantName:    "docker",
			wantVariant: "",
			wantVia:     "mountinfo",
		},
		{
			name: "cri-o detection",
			mountInfo: `/var/lib/containers/storage/overlay/abc123/merged`,
			wantName:    "cri-o",
			wantVariant: "",
			wantVia:     "mountinfo",
		},
		{
			name: "podman detection",
			mountInfo: `/home/user/.local/share/containers/storage/overlay`,
			wantName:    "podman",
			wantVariant: "",
			wantVia:     "mountinfo",
		},
		{
			name:      "unknown when no signatures match",
			mountInfo: `/proc/sys/kernel/hostname`,
			wantName:  "unknown",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := detectFromMountInfo(tt.mountInfo)
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
			if tt.wantName != "unknown" {
				if got.Variant != tt.wantVariant {
					t.Errorf("Variant = %q, want %q", got.Variant, tt.wantVariant)
				}
				if got.DetectionVia != tt.wantVia {
					t.Errorf("DetectionVia = %q, want %q", got.DetectionVia, tt.wantVia)
				}
			}
		})
	}
}

func TestDetectFromCgroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cgroup    string
		wantName  string
	}{
		{
			name:     "containerd cgroup",
			cgroup:   "12:memory:/kubepods/burstable/pod123/containerd-abc",
			wantName: "containerd",
		},
		{
			name:     "k3s cgroup is containerd, not docker",
			cgroup:   "12:memory:/k3s/pod123/abc",
			wantName: "containerd",
		},
		{
			name:     "docker cgroup",
			cgroup:   "12:memory:/docker/abc123",
			wantName: "docker",
		},
		{
			name:     "cri-o cgroup",
			cgroup:   "12:memory:/crio-abc123",
			wantName: "cri-o",
		},
		{
			name:     "podman cgroup",
			cgroup:   "12:memory:/machine.slice/podman-abc123",
			wantName: "podman",
		},
		{
			name:     "unknown cgroup",
			cgroup:   "12:memory:/system.slice/init.scope",
			wantName: "unknown",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := detectFromCgroup(tt.cgroup)
			if got.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tt.wantName)
			}
		})
	}
}

func TestRuntimeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		runtime Runtime
		want    string
	}{
		{Runtime{Name: "containerd", Variant: "k3s"}, "containerd (k3s)"},
		{Runtime{Name: "docker", Variant: ""}, "docker"},
		{Runtime{Name: "unknown"}, "unknown"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.want, func(t *testing.T) {
			t.Parallel()
			got := tt.runtime.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
