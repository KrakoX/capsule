package filesystem

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DockerSocket represents a detected docker socket
type DockerSocket struct {
	Path       string
	Valid      bool // Tested via HTTP request
	Accessible bool // Can read the file
}

// FindDockerSockets searches for docker.sock files and tests them
func FindDockerSockets() []DockerSocket {
	commonPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/.dockerenv",
	}

	var sockets []DockerSocket

	// Check common paths first
	for _, path := range commonPaths {
		if info, err := os.Stat(path); err == nil {
			if info.Mode()&os.ModeSocket != 0 {
				socket := DockerSocket{
					Path:       path,
					Accessible: true,
					Valid:      testDockerSocket(path),
				}
				sockets = append(sockets, socket)
			}
		}
	}

	// Walk filesystem for other sockets (limit search to /var/run and /run)
	searchPaths := []string{"/var/run", "/run"}
	for _, searchPath := range searchPaths {
		_ = filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}

			// Check if it's a socket with "docker" in the name
			if info.Mode()&os.ModeSocket != 0 && strings.Contains(strings.ToLower(path), "docker") {
				// Avoid duplicates
				exists := false
				for _, s := range sockets {
					if s.Path == path {
						exists = true
						break
					}
				}

				if !exists {
					socket := DockerSocket{
						Path:       path,
						Accessible: true,
						Valid:      testDockerSocket(path),
					}
					sockets = append(sockets, socket)
				}
			}

			return nil
		})
	}

	return sockets
}

// testDockerSocket tests if a socket is a valid Docker socket
// by attempting to connect and send a minimal HTTP request
func testDockerSocket(path string) bool {
	// Try to connect to the Unix socket
	conn, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()

	// Set a read deadline
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))

	// Send a minimal HTTP request to /version endpoint
	request := "GET /version HTTP/1.0\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		return false
	}

	// Read response
	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}

	// Check for HTTP 200 response
	response := string(buf[:n])
	return strings.Contains(response, "HTTP/") && strings.Contains(response, "200")
}

// HasValidDockerSocket checks if any valid docker sockets exist
func HasValidDockerSocket(sockets []DockerSocket) bool {
	for _, s := range sockets {
		if s.Valid {
			return true
		}
	}
	return false
}
