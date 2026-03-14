package kubernetes

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
)

// ServiceAccount represents Kubernetes service account information
type ServiceAccount struct {
	Name      string
	Namespace string
	Token     bool // Token file exists
	CACert    bool // CA certificate exists
	IsDefault bool // Using default service account
}

const serviceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

// GetServiceAccount detects and reads Kubernetes service account information
func GetServiceAccount() *ServiceAccount {
	// Check if service account directory exists
	if _, err := os.Stat(serviceAccountPath); os.IsNotExist(err) {
		return nil
	}

	sa := &ServiceAccount{}

	// Read namespace
	if namespace := readFileString(serviceAccountPath + "/namespace"); namespace != "" {
		sa.Namespace = strings.TrimSpace(namespace)
	}

	// Check if token exists (don't read it - just check presence)
	if _, err := os.Stat(serviceAccountPath + "/token"); err == nil {
		sa.Token = true
	}

	// Check if CA cert exists
	if _, err := os.Stat(serviceAccountPath + "/ca.crt"); err == nil {
		sa.CACert = true
	}

	// Parse SA name from JWT token: payload contains sub=system:serviceaccount:<ns>:<name>
	sa.Name = saNameFromToken(serviceAccountPath + "/token")
	if sa.Name == "" {
		sa.Name = os.Getenv("SERVICE_ACCOUNT_NAME")
	}
	if sa.Name == "" {
		sa.Name = "default"
	}

	sa.IsDefault = (sa.Name == "default")

	return sa
}

// IsK8sEnvironment checks if running in a Kubernetes environment
func IsK8sEnvironment() bool {
	_, err := os.Stat(serviceAccountPath)
	return err == nil
}

// saNameFromToken parses the service account name from the JWT token's sub claim.
// The sub field has the form "system:serviceaccount:<namespace>:<sa-name>".
func saNameFromToken(tokenPath string) string {
	tokenData, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.TrimSpace(string(tokenData)), ".")
	if len(parts) < 2 {
		return ""
	}
	// JWT payload is base64url-encoded (no padding)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	// sub = "system:serviceaccount:<namespace>:<sa-name>"
	segments := strings.Split(claims.Sub, ":")
	if len(segments) == 4 {
		return segments[3]
	}
	return ""
}

// readFileString reads a file and returns its content as a trimmed string
func readFileString(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
