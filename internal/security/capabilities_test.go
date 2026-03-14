package security

import (
	"testing"
)

func TestDecodeCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		hexStr string
		want   []string
	}{
		{
			name:   "zero bitmask returns empty",
			hexStr: "0000000000000000",
			want:   []string{},
		},
		{
			name:   "CAP_CHOWN is bit 0",
			hexStr: "0000000000000001",
			want:   []string{"CAP_CHOWN"},
		},
		{
			name:   "CAP_SYS_ADMIN is bit 21",
			hexStr: "0000000000200000",
			want:   []string{"CAP_SYS_ADMIN"},
		},
		{
			name:   "multiple caps: CHOWN + DAC_OVERRIDE",
			hexStr: "0000000000000003",
			want:   []string{"CAP_CHOWN", "CAP_DAC_OVERRIDE"},
		},
		{
			name:   "0x prefix is handled",
			hexStr: "0x0000000000000001",
			want:   []string{"CAP_CHOWN"},
		},
		{
			name:   "invalid hex returns empty",
			hexStr: "zzzzzz",
			want:   []string{},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := decodeCapabilities(tt.hexStr)
			if len(got) != len(tt.want) {
				t.Fatalf("decodeCapabilities(%q) = %v, want %v", tt.hexStr, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("index %d: got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestAssessRisk(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		caps []string
		want string
	}{
		{
			name: "empty caps is LOW",
			caps: []string{},
			want: "LOW",
		},
		{
			name: "non-dangerous caps is LOW",
			caps: []string{"CAP_CHOWN", "CAP_KILL"},
			want: "LOW",
		},
		{
			name: "more than 5 non-dangerous caps is MEDIUM",
			caps: []string{"CAP_CHOWN", "CAP_KILL", "CAP_NET_BIND_SERVICE", "CAP_SETUID", "CAP_SETGID", "CAP_FOWNER"},
			want: "MEDIUM",
		},
		{
			name: "single dangerous cap is HIGH",
			caps: []string{"CAP_SYS_ADMIN"},
			want: "HIGH",
		},
		{
			name: "two dangerous caps is CRITICAL",
			caps: []string{"CAP_SYS_ADMIN", "CAP_SYS_PTRACE"},
			want: "CRITICAL",
		},
		{
			name: "three dangerous caps is CRITICAL",
			caps: []string{"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_SYS_MODULE"},
			want: "CRITICAL",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := assessRisk(tt.caps)
			if got != tt.want {
				t.Errorf("assessRisk(%v) = %q, want %q", tt.caps, got, tt.want)
			}
		})
	}
}

func TestHasDangerousCapability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		caps CapabilitySet
		want bool
	}{
		{
			name: "no caps",
			caps: CapabilitySet{},
			want: false,
		},
		{
			name: "safe caps only",
			caps: CapabilitySet{Effective: []string{"CAP_CHOWN", "CAP_KILL"}},
			want: false,
		},
		{
			name: "SYS_ADMIN is dangerous",
			caps: CapabilitySet{Effective: []string{"CAP_CHOWN", "CAP_SYS_ADMIN"}},
			want: true,
		},
		{
			name: "DAC_READ_SEARCH is dangerous",
			caps: CapabilitySet{Effective: []string{"CAP_DAC_READ_SEARCH"}},
			want: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.caps.HasDangerousCapability()
			if got != tt.want {
				t.Errorf("HasDangerousCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseNoNewPrivs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status string
		want   bool
	}{
		{
			name:   "NoNewPrivs 1 means true",
			status: "Name:\tsh\nNoNewPrivs:\t1\nUid:\t0\n",
			want:   true,
		},
		{
			name:   "NoNewPrivs 0 means false",
			status: "Name:\tsh\nNoNewPrivs:\t0\nUid:\t0\n",
			want:   false,
		},
		{
			name:   "missing NoNewPrivs line is false",
			status: "Name:\tsh\nUid:\t0\n",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := parseNoNewPrivs(tt.status)
			if got != tt.want {
				t.Errorf("parseNoNewPrivs() = %v, want %v", got, tt.want)
			}
		})
	}
}
