#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
MANIFESTS="$SCRIPT_DIR/manifests"
NAMESPACE="ci-test"
TIMEOUT=90

# ── Detect node architecture and select binary ────────────────────────────────
NODE_ARCH=$(kubectl get node minikube -o jsonpath='{.status.nodeInfo.architecture}' 2>/dev/null || echo "amd64")
echo "Node architecture: $NODE_ARCH"

if [[ "$NODE_ARCH" == "arm64" ]]; then
    BINARY="$PROJECT_DIR/capsule-linux-arm64"
    if [[ ! -f "$BINARY" ]]; then
        echo "Building linux/arm64 binary..."
        GOOS=linux GOARCH=arm64 go build -trimpath \
            -ldflags "-X main.version=1.0.0 -s -w" \
            -o "$BINARY" "$PROJECT_DIR"
    fi
else
    BINARY="$PROJECT_DIR/capsule-linux-amd64"
    if [[ ! -f "$BINARY" ]]; then
        echo "Building linux/amd64 binary..."
        GOOS=linux GOARCH=amd64 go build -trimpath \
            -ldflags "-X main.version=1.0.0 -s -w" \
            -o "$BINARY" "$PROJECT_DIR"
    fi
fi

echo "Binary: $BINARY"
echo ""

# ── Namespace with privileged pod-security labels ─────────────────────────────
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
kubectl label namespace "$NAMESPACE" \
    pod-security.kubernetes.io/enforce=privileged \
    pod-security.kubernetes.io/audit=privileged \
    pod-security.kubernetes.io/warn=privileged \
    --overwrite >/dev/null

# ── Helper ────────────────────────────────────────────────────────────────────
run_scenario() {
    local display_name="$1"
    local manifest="$2"
    local pod_name="$3"
    local binary_dest="${4:-/ci}"

    printf "\n\033[1m══════════════════════════════════════════════════════\033[0m\n"
    printf "\033[1m  SCENARIO: %-42s\033[0m\n" "$display_name"
    printf "\033[1m══════════════════════════════════════════════════════\033[0m\n\n"

    kubectl apply -f "$manifest" -n "$NAMESPACE" >/dev/null 2>&1

    # Wait for Running phase
    local elapsed=0
    while [[ $elapsed -lt $TIMEOUT ]]; do
        local phase
        phase=$(kubectl get pod -n "$NAMESPACE" "$pod_name" \
            -o jsonpath='{.status.phase}' 2>/dev/null || echo "Pending")
        [[ "$phase" == "Running" ]] && break
        if [[ "$phase" == "Failed" ]]; then
            echo "[FAIL] Pod failed to start"
            kubectl logs -n "$NAMESPACE" "$pod_name" 2>/dev/null | tail -5 || true
            kubectl delete -f "$manifest" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1
            return 1
        fi
        sleep 3
        ((elapsed += 3))
    done

    if [[ $elapsed -ge $TIMEOUT ]]; then
        echo "[FAIL] Pod did not reach Running state within ${TIMEOUT}s"
        kubectl delete -f "$manifest" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1
        return 1
    fi

    # Copy binary and run
    kubectl cp "$BINARY" "$NAMESPACE/$pod_name:$binary_dest" 2>/dev/null
    kubectl exec -n "$NAMESPACE" "$pod_name" -- chmod +x "$binary_dest" 2>/dev/null || true
    kubectl exec -n "$NAMESPACE" "$pod_name" -- "$binary_dest"

    kubectl delete -f "$manifest" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1
}

# ── Scenarios ─────────────────────────────────────────────────────────────────
run_scenario "Default pod"                    "$MANIFESTS/01-default.yaml"        ci-default
run_scenario "Privileged pod"                 "$MANIFESTS/02-privileged.yaml"     ci-privileged
run_scenario "hostNetwork: true"              "$MANIFESTS/03-host-network.yaml"   ci-host-network
run_scenario "hostPID: true"                  "$MANIFESTS/04-host-pid.yaml"       ci-host-pid
run_scenario "hostIPC: true"                  "$MANIFESTS/05-host-ipc.yaml"       ci-host-ipc
run_scenario "runAsUser: 1000 (non-root)"     "$MANIFESTS/06-non-root.yaml"       ci-non-root     /tmp/ci
run_scenario "readOnlyRootFilesystem: true"   "$MANIFESTS/07-readonly-root.yaml"  ci-readonly     /tmp/ci
run_scenario "Hardened (drop ALL + non-root)" "$MANIFESTS/08-hardened.yaml"       ci-hardened     /tmp/ci
run_scenario "cap-add: SYS_ADMIN"             "$MANIFESTS/09-cap-sys-admin.yaml"  ci-cap-sys-admin
run_scenario "Custom service account"         "$MANIFESTS/10-custom-sa.yaml"      ci-custom-sa
run_scenario "Ubuntu 22.04 (SUID binaries)"   "$MANIFESTS/11-ubuntu-suid.yaml"    ci-ubuntu-suid

# ── Cleanup ───────────────────────────────────────────────────────────────────
echo ""
echo "Deleting namespace $NAMESPACE..."
kubectl delete namespace "$NAMESPACE" --ignore-not-found >/dev/null 2>&1
echo "Done."
