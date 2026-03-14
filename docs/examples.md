# Example outputs

All outputs below were produced by running the binary directly inside a container:

```bash
docker run --rm -v $(pwd)/capsule:/capsule:ro <image> /capsule
```

---

## Default unprivileged container

```
=== CONTAINER SECURITY ASSESSMENT ===
capsule v1.0.0

=== CONTAINER RUNTIME ===
Runtime:          containerd
Detection Method: mountinfo

=== SECURITY PROFILE ===
Capabilities:
  Effective:   CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, ... (14 total)
  [HIGH] Dangerous capabilities present:
    - CAP_DAC_OVERRIDE
  Bounding:    14 capabilities
  NoNewPrivs:  false (can gain privileges via setuid)
  Risk Level:  HIGH

Namespaces:
  PID:    true   Net:   true   Mount: true
  UTS:    true   IPC:   true   User:  false
  Isolation:  STRONG

Security Profiles:
  Seccomp:  filtering
  AppArmor: docker-default (enforce)

Syscall Restrictions:
  [HIGH] 4 dangerous syscalls allowed:
    - chroot
    - setuid
    - setgid
    - ptrace
  Blocked: 6/10

=== FILESYSTEM ANALYSIS ===
[OK] No dangerous mounts detected

SUID Binaries: 0 found

[MEDIUM] Sensitive Writable Directories:
  /root (root home directory)
  /etc (system configuration)

=== NETWORK ANALYSIS ===
Interfaces: 1 found (eth0)
Isolation:  STRONG (single interface)
DNS Type:   custom

=== PROCESS ANALYSIS ===
PID 1:     /capsule
Security:  MEDIUM
```

---

## Privileged container (`--privileged`)

All 41 capabilities, seccomp disabled, AppArmor unconfined, all dangerous syscalls available:

```
=== SECURITY PROFILE ===
Capabilities:
  Effective:   CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, ... (41 total)
  [HIGH] Dangerous capabilities present:
    - CAP_DAC_OVERRIDE
    - CAP_DAC_READ_SEARCH
    - CAP_SYS_MODULE
    - CAP_SYS_PTRACE
    - CAP_SYS_ADMIN
  Bounding:    41 capabilities
  NoNewPrivs:  false (can gain privileges via setuid)
  Risk Level:  CRITICAL

Security Profiles:
  Seccomp:  disabled (all syscalls allowed)
  AppArmor: unconfined (no MAC enforcement)

Syscall Restrictions:
  [HIGH] 10 dangerous syscalls allowed:
    - mount
    - umount2
    - ptrace
    - reboot
    - setns
    - unshare
    - pivot_root
    - chroot
    - setuid
    - setgid
```

---

## Container escape vector — Docker socket mounted

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd)/capsule:/capsule:ro alpine /capsule
```

```
=== FILESYSTEM ANALYSIS ===
[CRITICAL] CONTAINER ESCAPE VECTOR DETECTED
Valid Docker Socket(s) found:
  - /var/run/docker.sock (escape possible)
  - /run/docker.sock (escape possible)

[CRITICAL] Critical Mounts (escape vectors):
  tmpfs -> /run/docker.sock
    Reason: docker socket - container escape
```

---

## Host network namespace (`--network=host`)

`Net: false` indicates the network namespace is shared with the host:

```
=== SECURITY PROFILE ===
Namespaces:
  PID:    true   Net:   false   Mount: true
  UTS:    true   IPC:   true    User:  false
  Isolation:  STRONG

=== NETWORK ANALYSIS ===
Interfaces: 2 found (eth0, docker0)
Isolation:  NONE (host network)
```

---

## Host PID namespace (`--pid=host`)

`PID: false` indicates the PID namespace is shared. The process runs at a host-level PID and PID 1 is the host's init:

```
=== SECURITY PROFILE ===
Namespaces:
  PID:    false   Net:   true   Mount: true
  UTS:    true    IPC:   true   User:  false
  Isolation:  STRONG

=== PROCESS ANALYSIS ===
PID 1:     /sbin/init
Current:   PID 4950: /capsule
```

---

## Extra dangerous capability (`--cap-add=SYS_ADMIN`)

Two dangerous capabilities present → CRITICAL risk, 8 syscalls unlocked:

```
=== SECURITY PROFILE ===
Capabilities:
  Effective:   CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, ... (15 total)
  [HIGH] Dangerous capabilities present:
    - CAP_DAC_OVERRIDE
    - CAP_SYS_ADMIN
  Risk Level:  CRITICAL

Syscall Restrictions:
  [HIGH] 8 dangerous syscalls allowed:
    - mount
    - umount2
    - ptrace
    - setns
    - unshare
    - chroot
    - setuid
    - setgid
  Blocked: 2/10
```

---

## Kubernetes pod (default)

Service account, cluster DNS, and host access flags are automatically detected:

```
=== KUBERNETES CONTEXT ===
Service Account:
  Name:       default (using default SA)
  Namespace:  production
  Token:      true
  CA Cert:    true

Pod Security Context:
  runAsUser:              0 (root)
  runAsGroup:             0
  runAsNonRoot:           false
  readOnlyRootFilesystem: false

Host Access:
  hostNetwork: false
  hostPID:     false
  hostIPC:     false

=== NETWORK ANALYSIS ===
Interfaces: 1 found (eth0)
Isolation:  STRONG (single interface)
DNS Type:   kubernetes
Nameserver: 10.96.0.10
```

---

## Hardened pod (drop ALL capabilities, non-root, read-only root)

```
=== SECURITY PROFILE ===
Capabilities:
  Effective:   none (restricted)
  Bounding:    0 capabilities
  NoNewPrivs:  true
  Risk Level:  LOW

=== KUBERNETES CONTEXT ===
Pod Security Context:
  runAsUser:              1000
  runAsGroup:             1000
  runAsNonRoot:           true
  readOnlyRootFilesystem: true
```
