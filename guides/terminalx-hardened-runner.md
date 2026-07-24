# TerminalX hardened Daytona runner

This fork keeps `b5a5d9e78d76c8bcf351f2049620250e0f34eea4` as its immutable Daytona base.
TerminalX production deployments pin a reviewed descendant commit; they must never attest the base
commit itself as isolated because ordinary non-GPU Sandboxes at that revision are privileged.

The hardened profile is a dedicated-runner contract, not a compatibility mode for arbitrary
Daytona workloads. It refuses startup or Sandbox creation whenever the effective boundary cannot
match the signed TerminalX deployment manifest.

## Required runner configuration

```dotenv
TERMINALX_HARDENED=true
TERMINALX_SANDBOX_IMAGE_ID=sha256:<exact-64-hex-config-digest>
TERMINALX_SANDBOX_SNAPSHOT_REF=<exact-platform-snapshot-ref>
TERMINALX_DOCKER_SERVER_VERSION=<exact-reviewed-engine-version>
TERMINALX_CONTAINERD_COMMIT=<exact-reviewed-containerd-build-id>
TERMINALX_RUNC_COMMIT=<exact-reviewed-runc-build-id>
USE_SNAPSHOT_ENTRYPOINT=true
RESOURCE_LIMITS_DISABLED=false
INTER_SANDBOX_NETWORK_ENABLED=false
GPU_ENABLED=false
MOUNT_KVM_TO_ANDROID_SANDBOX=false
INITIALIZE_DAEMON_TELEMETRY=false
CONTAINER_NETWORK=
CONTAINER_RUNTIME=
SSH_GATEWAY_ENABLE=false
```

The Docker backing filesystem must be XFS with project-quota support, and Docker must report its
exact built-in seccomp profile, cgroup v2, `runc` as its default runtime, every required cgroup
limit, and live-restore disabled. Docker, containerd, and runc must match the exact signed build
identities supplied to the runner; version tags alone are not accepted.

The only accepted Sandbox image has all of these properties:

- its inspected content-addressable image ID exactly equals `TERMINALX_SANDBOX_IMAGE_ID`;
- it is preloaded by the deployment, requested through the one exact
  `TERMINALX_SANDBOX_SNAPSHOT_REF`, and still resolves to the separately pinned image ID;
- `io.terminalx.sandbox.profile=v1`;
- entrypoint `/usr/local/bin/terminalx-sandbox-init`;
- no image-declared volumes; and
- a root init that starts the root-owned TerminalX supervisor, drops the Daytona daemon and every
  agent/tool process to the `terminalx` identity, and keeps supervisor keys/state unreadable by that
  identity.

Runner startup inspects this preloaded image and every existing container before
the API can become available. The Docker host is dedicated: an existing non-TerminalX container,
or any image, container-boundary, or network-policy drift, aborts startup.

## Enforced v1 boundary

The runner rejects GPU/Android/device workloads, linked Sandboxes, host or shared volumes,
entrypoint overrides, environment/OTEL injection, skipped startup, resource resizing/recovery,
generic image pull/tag/push/removal or builds, Docker-commit snapshots, and generic backups. These are closed
because they could copy root-owned per-assignment signing material into an image or registry.

Containers are non-privileged, drop all ambient capabilities, add back only the root init's
`CHOWN`, `KILL`, `SETGID`, and `SETUID` capabilities, and set `no-new-privileges`. Each Sandbox has
finite CPU, memory/swap, XFS overlay storage, and a 256-PID cgroup ceiling. It has no external bind,
mount, linked network, port publication, or device request. Create requests are capped at 64 CPUs,
512 GiB memory, and 4096 GiB disk so integer overflow cannot turn a finite request into an
unbounded Docker limit. IPC and cgroup namespaces are explicitly private; healthchecks, tmpfs,
container logging, shared namespace modes, and daemon-dependent security defaults are rejected.

The dedicated, labeled `runner-bridge` is an IPv4-only Docker `internal` bridge with inter-container
communication disabled. Default-deny IPv4 rules are also installed synchronously before
`ContainerStart`. A dedicated DOCKER-USER chain drops forwarded egress. INPUT rules prevent a
Sandbox from initiating calls to runner-host services while allowing established replies to
runner-initiated daemon requests. Rules are installed fail-closed without clearing a live chain
first.

The monitor validates every container again on stream reconnect, container update, and network
connect/disconnect events. A running boundary drift or enforcement failure immediately kills all
workloads on the dedicated host and terminates the runner. Stop/kill events retain DROP rules until
the container is destroyed, and firewall reconciliation inserts a known-safe head before leaving
older duplicate rules in place, so no delete-before-insert window exists.

## Deliberately closed capabilities

V1 permits no direct egress and no generic Sandbox checkpoint. Broker-only egress and a protected
checkpoint path require their own signed policy and adversarial evidence before activation. An API
request, operator statement, image label, or branch name is not enforcement evidence: the
root-owned supervisor must measure the live namespaces, identities, mounts, cgroups, capabilities,
seccomp state, image identity, and network controls and sign those claims for the exact TerminalX
Assignment generation.
