# Example outputs

All outputs below were produced by running the binary directly inside a container.
The binary is baked into a test image at build time — no volume mounts for delivery:

```bash
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.version=1.0.0" -o capsule-linux-arm64 .
docker build -t capsule-test:latest .
docker run --rm capsule-test:latest
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
  Bounding:    14 capabilities
  NoNewPrivs:  false (can gain privileges via setuid)
  Risk Level:  MEDIUM

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
    - ptrace
    - setgid
    - setuid
  Blocked: 6/10

=== FILESYSTEM ANALYSIS ===
[HIGH] High Risk Mounts:
  cgroup -> /sys/fs/cgroup (kernel interface access)
  proc -> /proc/bus (kernel interface access)
  proc -> /proc/fs (kernel interface access)
  proc -> /proc/irq (kernel interface access)
  proc -> /proc/sys (kernel interface access)
  ... and 1 more

SUID Binaries: 0 found

[MEDIUM] Sensitive Writable Directories:
  /root (root home directory)
  /etc (system configuration)
  /var/log (system logs)
  /usr/local (system binaries)

[MEDIUM] Development Tools (attack vectors):
  shells: sh
  network: wget, nc

=== NETWORK ANALYSIS ===
Interfaces: 1 found (eth0)
Isolation:  STRONG (single interface)
DNS Type:   custom
Nameserver: 192.168.5.1

=== PROCESS ANALYSIS ===
PID 1:     /capsule
Current:   PID 1: /capsule
Security:  MEDIUM
```

---

## Privileged container (`--privileged`)

All 41 capabilities, seccomp disabled, AppArmor unconfined, all dangerous syscalls available:

```bash
docker run --rm --privileged capsule-test:latest
```

```
=== SECURITY PROFILE ===
Capabilities:
  Effective:   CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, ... (41 total)
  [HIGH] Dangerous capabilities present:
    - CAP_SYS_MODULE
    - CAP_SYS_RAWIO
    - CAP_SYS_PTRACE
    - CAP_SYS_ADMIN
    - CAP_SYS_BOOT
    - CAP_BPF
  [MEDIUM] Notable capabilities present:
    - CAP_NET_ADMIN
    - CAP_SYSLOG
    - CAP_PERFMON
    - CAP_CHECKPOINT_RESTORE
  Bounding:    41 capabilities
  NoNewPrivs:  false (can gain privileges via setuid)
  Risk Level:  CRITICAL

Security Profiles:
  Seccomp:  disabled (all syscalls allowed)
  AppArmor: unconfined (no MAC enforcement)

Syscall Restrictions:
  [HIGH] 10 dangerous syscalls allowed:
    - chroot
    - mount
    - pivot_root
    - ptrace
    - reboot
    - setgid
    - setns
    - setuid
    - umount2
    - unshare
```

---

## Container escape vector — Docker socket mounted

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock capsule-test:latest
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

```bash
docker run --rm --network=host capsule-test:latest
```

```
=== SECURITY PROFILE ===
Namespaces:
  PID:    true   Net:   false   Mount: true
  UTS:    true   IPC:   true   User:  false
  Isolation:  STRONG

=== NETWORK ANALYSIS ===
Interfaces: 3 found (eth0, docker0, br-c6202fa5246e)
Isolation:  NONE (host network)
```

---

## Host PID namespace (`--pid=host`)

`PID: false` indicates the PID namespace is shared. The process runs at a host-level PID and PID 1 is the host's init:

```bash
docker run --rm --pid=host capsule-test:latest
```

```
=== SECURITY PROFILE ===
Namespaces:
  PID:    false   Net:   true   Mount: true
  UTS:    true   IPC:   true   User:  false
  Isolation:  STRONG

=== PROCESS ANALYSIS ===
PID 1:     /sbin/init
Current:   PID 3969: /capsule
```

---

## Extra dangerous capability (`--cap-add=SYS_ADMIN`)

One severe capability present → HIGH risk, 8 syscalls unlocked:

```bash
docker run --rm --cap-add=SYS_ADMIN capsule-test:latest
```

```
=== SECURITY PROFILE ===
Capabilities:
  Effective:   CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER, ... (15 total)
  [HIGH] Dangerous capabilities present:
    - CAP_SYS_ADMIN
  Bounding:    15 capabilities
  NoNewPrivs:  false (can gain privileges via setuid)
  Risk Level:  HIGH

Syscall Restrictions:
  [HIGH] 8 dangerous syscalls allowed:
    - chroot
    - mount
    - ptrace
    - setgid
    - setns
    - setuid
    - umount2
    - unshare
  Blocked: 2/10
```
