# capsule

A fast, zero-dependency container security assessment tool. Drop it inside any container to immediately understand its security posture — capabilities, namespaces, seccomp, AppArmor, dangerous mounts, Kubernetes context, and more.

[![CI](https://github.com/KrakoX/capsule/actions/workflows/ci.yml/badge.svg)](https://github.com/KrakoX/capsule/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/KrakoX/capsule)](https://goreportcard.com/report/github.com/KrakoX/capsule)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Features

- **Container Runtime Detection** — containerd (K3s, RKE2, MicroK8s, EKS), Docker, CRI-O, Podman
- **Linux Capabilities** — decodes all 41 capabilities, flags dangerous ones, assesses risk level
- **Namespace Isolation** — detects host PID (`--pid=host`) and host network (`--network=host`) sharing
- **Seccomp / AppArmor** — profile detection and enforcement status
- **Dangerous Syscalls** — tests mount, ptrace, reboot, setns, unshare, pivot_root, and more
- **Kubernetes Context** — service account, pod security context, hostNetwork/hostPID/hostIPC
- **Filesystem Analysis** — dangerous mounts, SUID binaries, writable directories, Docker socket detection
- **Network Analysis** — interface enumeration, isolation level, DNS type
- **Process Analysis** — PID 1 inspection, root detection, shell access

---

## Installation

### Pre-built binary (recommended)

```bash
# linux/amd64
curl -sSfL https://github.com/KrakoX/capsule/releases/latest/download/capsule_linux_amd64.tar.gz \
  | tar -xz capsule

# linux/arm64
curl -sSfL https://github.com/KrakoX/capsule/releases/latest/download/capsule_linux_arm64.tar.gz \
  | tar -xz capsule
```

### go install

```bash
go install github.com/KrakoX/capsule@latest
```

### Build from source

```bash
git clone https://github.com/KrakoX/capsule.git
cd capsule
make build
```

---

## Usage

```bash
# Human-readable output (default)
./capsule

# JSON for automation / pipelines
./capsule -format json

# Show only HIGH and CRITICAL findings
./capsule -risk-only

# Suppress informational messages
./capsule -quiet

# Write output to a file
./capsule -output /tmp/report.json -format json

# Print version
./capsule -version
```

See [docs/examples.md](docs/examples.md) for sample outputs across common scenarios.

---

## Output formats

| Flag | Description |
|------|-------------|
| `-format text` | Colored terminal output (default) |
| `-format json` | Structured JSON — suitable for `jq`, logging pipelines, or SIEM ingest |

---

## Background

`capsule` builds on the ideas of [amicontained](https://github.com/genuinetools/amicontained) — a useful tool from the genuinetools project — with updated runtime detection, Kubernetes context awareness, and a single external dependency.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure policy.

## License

MIT — see [LICENSE](LICENSE).
