package filesystem

import (
	"testing"
)

func TestAssessMountRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		source   string
		target   string
		fstype   string
		wantRisk string // empty string means nil (no risk)
	}{
		// CRITICAL
		{
			name:     "docker socket is CRITICAL",
			source:   "/run/docker.sock",
			target:   "/var/run/docker.sock",
			fstype:   "bind",
			wantRisk: "CRITICAL",
		},
		{
			name:     "containerd socket is CRITICAL",
			source:   "/run/containerd/containerd.sock",
			target:   "/run/containerd/containerd.sock",
			fstype:   "bind",
			wantRisk: "CRITICAL",
		},
		// HIGH
		{
			name:     "host filesystem path is HIGH",
			source:   "/",
			target:   "/host/etc",
			fstype:   "bind",
			wantRisk: "HIGH",
		},
		{
			name:     "device node is HIGH",
			source:   "/dev/sda",
			target:   "/dev/sda",
			fstype:   "ext4",
			wantRisk: "HIGH",
		},
		{
			name:     "proc subpath is HIGH",
			source:   "proc",
			target:   "/proc/sys",
			fstype:   "proc",
			wantRisk: "HIGH",
		},
		// MEDIUM
		{
			name:     "tmpfs on /dev is MEDIUM",
			source:   "tmpfs",
			target:   "/dev",
			fstype:   "tmpfs",
			wantRisk: "MEDIUM",
		},
		// Safe (nil)
		{
			name:     "/dev/null is safe",
			source:   "/dev/null",
			target:   "/dev/null",
			fstype:   "bind",
			wantRisk: "",
		},
		{
			name:     "regular app mount is safe",
			source:   "/data/app",
			target:   "/app",
			fstype:   "ext4",
			wantRisk: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessMountRisk(tt.source, tt.target, tt.fstype)
			if tt.wantRisk == "" {
				if got != nil {
					t.Errorf("expected nil risk for %q, got %+v", tt.target, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected risk %q for %q, got nil", tt.wantRisk, tt.target)
			}
			if got.Risk != tt.wantRisk {
				t.Errorf("Risk = %q, want %q (target=%q, reason=%q)", got.Risk, tt.wantRisk, tt.target, got.Reason)
			}
		})
	}
}

func TestGetCriticalMounts(t *testing.T) {
	t.Parallel()

	mounts := []MountRisk{
		{Target: "/var/run/docker.sock", Risk: "CRITICAL"},
		{Target: "/host/etc", Risk: "HIGH"},
		{Target: "/dev/sda", Risk: "HIGH"},
		{Target: "/dev", Risk: "MEDIUM"},
	}

	critical := GetCriticalMounts(mounts)
	if len(critical) != 1 {
		t.Fatalf("GetCriticalMounts returned %d items, want 1", len(critical))
	}
	if critical[0].Target != "/var/run/docker.sock" {
		t.Errorf("unexpected critical mount: %q", critical[0].Target)
	}
}

func TestGetHighRiskMounts(t *testing.T) {
	t.Parallel()

	mounts := []MountRisk{
		{Target: "/var/run/docker.sock", Risk: "CRITICAL"},
		{Target: "/host/etc", Risk: "HIGH"},
		{Target: "/dev", Risk: "MEDIUM"},
	}

	high := GetHighRiskMounts(mounts)
	if len(high) != 2 {
		t.Fatalf("GetHighRiskMounts returned %d items, want 2", len(high))
	}
}
