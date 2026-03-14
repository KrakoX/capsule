package reporter

import (
	"encoding/json"
	"testing"

	"github.com/KrakoX/capsule/internal/runtime"
	"github.com/KrakoX/capsule/internal/security"
)

func TestReportToJSON(t *testing.T) {
	t.Parallel()

	r := Report{
		Runtime: runtime.Runtime{
			Name:         "containerd",
			Variant:      "k3s",
			DetectionVia: "mountinfo",
		},
		Security: SecurityReport{
			Capabilities: security.CapabilitySet{
				Effective: []string{"CAP_CHOWN"},
				RiskLevel: "LOW",
			},
			Seccomp:  "filtering",
			AppArmor: "unconfined",
		},
	}

	out, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error: %v", err)
	}
	if out == "" {
		t.Fatal("ToJSON() returned empty string")
	}

	// Verify it is valid JSON
	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("ToJSON() produced invalid JSON: %v\noutput: %s", err, out)
	}

	// Check top-level keys
	for _, key := range []string{"runtime", "security", "filesystem", "network", "process"} {
		if _, ok := parsed[key]; !ok {
			t.Errorf("JSON output missing key %q", key)
		}
	}

	// kubernetes is omitempty and should be absent
	if _, ok := parsed["kubernetes"]; ok {
		t.Error("kubernetes key present in JSON but should be omitted when nil")
	}
}

func TestReportToJSON_WithKubernetes(t *testing.T) {
	t.Parallel()

	r := Report{
		Kubernetes: &KubernetesReport{},
	}

	out, err := r.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON() error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := parsed["kubernetes"]; !ok {
		t.Error("kubernetes key missing from JSON when KubernetesReport is set")
	}
}
