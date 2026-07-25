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
TERMINALX_SUPERVISOR_RELAY_SHA256=<exact-64-hex-executable-digest>
TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256=<exact-64-hex-executable-digest>
TERMINALX_NODE_SHA256=<exact-64-hex-executable-digest>
TERMINALX_DEPLOYMENT_BINDING_INSTALLER_SHA256=<exact-64-hex-executable-digest>
TERMINALX_ISOLATION_PROBE_SHA256=<exact-64-hex-executable-digest>
TERMINALX_SANDBOX_ARTIFACT_DIGEST=<exact-64-hex-release-digest>
# Equality assertion only; the runner derives its identity from its own binary.
TERMINALX_EXPECTED_SOURCE_COMMIT=<exact-clean-40-hex-runner-vcs.revision>
TERMINALX_SECCOMP_PROFILE_SHA256=<exact-64-hex-profile-digest>
TERMINALX_BOOTSTRAP_AUTHORITY_KEY_ID=<platform-bootstrap-key-id>
TERMINALX_BOOTSTRAP_AUTHORITY_PUBLIC_KEY_FILE=/run/terminalx-secrets/bootstrap-authority.pem
TERMINALX_BOOTSTRAP_AUTHORITY_PUBLIC_KEY_SHA256=<exact-canonical-pem-digest>
TERMINALX_DEPLOYMENT_BINDING_KEY_ID=<runner-deployment-key-id>
TERMINALX_DEPLOYMENT_BINDING_PRIVATE_KEY_FILE=/run/terminalx-secrets/deployment-binding.pk8
TERMINALX_DEPLOYMENT_BINDING_PUBLIC_KEY_SHA256=<exact-canonical-public-pem-digest>
TERMINALX_ISOLATION_ATTESTOR_KEY_ID=<runner-isolation-key-id>
TERMINALX_ISOLATION_ATTESTOR_PRIVATE_KEY_FILE=/run/terminalx-secrets/isolation-attestor.pk8
TERMINALX_ISOLATION_ATTESTOR_PUBLIC_KEY_SHA256=<exact-canonical-public-pem-digest>
TERMINALX_EVIDENCE_TTL=60s
TERMINALX_DAYTONA_DAEMON_UID=10001
TERMINALX_AGENT_UID=10001
DAYTONA_RUNNER_TOKEN=<at-least-32-byte-high-entropy-credential>
ENABLE_TLS=true
TLS_CERT_FILE=/absolute/path/to/runner-certificate.pem
TLS_KEY_FILE=/absolute/path/to/runner-private-key.pem
USE_SNAPSHOT_ENTRYPOINT=true
RESOURCE_LIMITS_DISABLED=false
INTER_SANDBOX_NETWORK_ENABLED=false
GPU_ENABLED=false
MOUNT_KVM_TO_ANDROID_SANDBOX=false
INITIALIZE_DAEMON_TELEMETRY=false
ENVIRONMENT=production
API_LOG_REQUESTS=false
OTEL_LOGGING_ENABLED=false
OTEL_TRACING_ENABLED=false
OTEL_EXPORTER_OTLP_ENDPOINT=
OTEL_EXPORTER_OTLP_HEADERS=
# DOCKER_HOST, DOCKER_API_VERSION, DOCKER_CERT_PATH, and DOCKER_TLS_VERIFY must be unset.
CONTAINER_NETWORK=
CONTAINER_RUNTIME=
SSH_GATEWAY_ENABLE=false
```

The hardened runner must be built from a clean exact checkout with Go's `-buildvcs=true` and
`-trimpath` flags. Before initializing Docker, provider clients, or telemetry, it requires one
lowercase 40-hex `vcs.revision`, `vcs=git`, and `vcs.modified=false` from its embedded Go build
information. It then opens `/proc/self/exe`, verifies a stable regular-file identity before and
after reading, rejects a non-executable or group/world-writable artifact, and SHA-256 hashes those
live executable bytes. `TERMINALX_EXPECTED_SOURCE_COMMIT` is a required equality assertion over
that measured revision; it cannot select or replace the revision. The former
`TERMINALX_HARDENED_SOURCE_COMMIT` input is not accepted as identity. Fresh
signed effective-isolation claims include both the measured source commit and the lowercase
`runnerBinaryDigest`.

The Docker backing filesystem must be XFS with project-quota support, and Docker must report its
exact built-in seccomp profile, cgroup v2, `runc` as its default runtime, every required cgroup
limit, and live-restore disabled. Docker, containerd, and runc must match the exact signed build
identities supplied to the runner; version tags alone are not accepted. The bootstrap authority
pin and both runner private signing keys must be distinct. Key files are absolute, root-owned,
non-linked regular files under protected parent directories. Private keys are canonical Ed25519
PKCS#8 with mode `0400` or `0600`; the bootstrap public key is canonical SPKI PEM. The runner
zeroes its private-key copies during shutdown and never places them in an image, container
environment, label, response, or checkpoint. A hardened runner refuses
to start without TLS, its certificate and private-key paths, a high-entropy API credential, and
all fixed root-executable digests. It also requires the production environment, disables request
logging and every OpenTelemetry exporter before initialization, omits request instrumentation and
Swagger, and applies recursive provider-UUID, Docker-ID, and process-credential redaction to its
remaining local structured logs. TerminalX clients additionally verify a private CA and the runner
certificate's exact SubjectPublicKeyInfo digest.

The Docker API is pinned to the root-owned, non-world-accessible `/run/docker.sock`. Every new
connection rechecks the same socket inode, a root peer, and matching mount, network, PID, and user
namespaces. Docker environment overrides, alternate Unix sockets, TCP/SSH endpoints, and rootless
daemons are rejected before any Docker API request, so local firewall evidence cannot be combined
with a different execution daemon.

## Runner and daemon release identity

The hardened workflow reproducibly builds the linux/amd64 runner and daemon twice with
`-buildvcs=true`, rejects a byte mismatch, and makes each binary independently prove the workflow's
exact `github.sha`. It uploads and signs GitHub build-provenance attestations for both binaries and
their deterministic manifest. The manifest is UTF-8, one-line JSON with a trailing newline; before
the newline its exact schema and canonical key order are:

```json
{"artifacts":{"daemon":{"architecture":"amd64","binaryDigest":"<64-lowercase-hex>","operatingSystem":"linux","sourceCommit":"<40-lowercase-hex>"},"runner":{"architecture":"amd64","binaryDigest":"<64-lowercase-hex>","operatingSystem":"linux","sourceCommit":"<40-lowercase-hex>"}},"kind":"terminalx.daytona-hardened-runtime-artifacts","version":1}
```

Release consumers must verify the GitHub attestation's repository, workflow, ref, and exact source
revision, parse only this closed schema, require both `sourceCommit` values to equal the reviewed
production fork commit, and hash the downloaded binaries themselves. The Sandbox image builder
must accept the Daytona daemon only from that verified manifest and must set
`TERMINALX_DAYTONA_DAEMON_SHA256` from `artifacts.daemon.binaryDigest`; an operator-provided daemon
path plus a separately supplied digest or image label is not release evidence. Runner deployment
must likewise require `artifacts.runner.binaryDigest` to equal the executable it installs. The
TerminalX signed deployment manifest should additionally bind the SHA-256 of this entire runtime
artifact manifest, so release identity remains independently pinned after GitHub artifact download.

The only accepted Sandbox image has all of these properties:

- its inspected content-addressable image ID exactly equals `TERMINALX_SANDBOX_IMAGE_ID`;
- it is preloaded by the deployment, requested through the one exact
  `TERMINALX_SANDBOX_SNAPSHOT_REF`, and still resolves to the separately pinned image ID;
- `io.terminalx.sandbox.profile=v1`;
- `io.terminalx.supervisor-relay.sha256` and
  `io.terminalx.assignment-bootstrap.sha256`, `io.terminalx.node.sha256`,
  `io.terminalx.deployment-binding-installer.sha256`, and
  `io.terminalx.isolation-probe.sha256` equal the runner's independent executable pins;
- entrypoint `/usr/local/bin/terminalx-sandbox-init`;
- no image-declared volumes; and
- root-owned regular mode-`0555` executables at
  `/usr/local/libexec/terminalx/terminalx-assignment-bootstrap` and
  `/usr/local/libexec/terminalx/terminalx-supervisor-relay`; and
- a root init that starts the Daytona daemon as `terminalx`, waits fail-closed for atomically
  installed assignment material, then starts the root-owned TerminalX supervisor while keeping its
  keys, socket, and state unreadable by `terminalx`.

Runner startup inspects this preloaded image and every existing container before
the API can become available. The Docker host is dedicated: an existing non-TerminalX container,
or any image, container-boundary, or network-policy drift, aborts startup.

The Daytona API projects exactly three reserved public Sandbox labels into create-job metadata:
`terminalx.artifact`, `terminalx.revision`, and `terminalx.plan`. A hardened runner accepts no
other create metadata, requires canonical lowercase SHA-256 artifact/plan digests and a positive
JavaScript-safe canonical revision, compares the artifact to its deployment pin, and copies the
three values into immutable Docker labels. A partial binding, an organization metadata injection,
or a later database-label mutation cannot become container identity. The provisional container
remains inactive until the root installer receives the separately signed, provider-bound
activation material.

Hardened create/start responses are deliberately **provisional**. The runner waits for the
container to be running and revalidates its exact immutable boundary, but it never probes the
ordinary Daytona TCP port `2280` and never publishes a daemon version. A Sandbox becomes eligible
for TerminalX work only after the root bootstrap has installed the signed provider-bound material
and the caller has verified fresh signed effective-isolation evidence through the root relay.

## Narrow root protocol

The authenticated TLS runner exposes exactly two hardened-only routes; neither accepts an
executable path, argument, environment variable, uid, working directory, TTY, or privilege flag.
Before every invocation the runner fully revalidates the running container and copies, measures,
and constant-time compares the selected root executable against its independent SHA-256 pin.

`POST /sandboxes/:sandboxId/terminalx-assignment-bootstrap` accepts at most 3 MiB with content type
`application/vnd.terminalx.assignment-bootstrap.v1` and requires
`Accept: application/vnd.terminalx.assignment-bootstrap-installed.v1+json`. The one-shot
provisioner verifies the signed assignment and image-owned trust pins, installs root-only files
with create-once semantics, fsyncs them, and returns at most 64 KiB of public JSON. Exit `64` maps
to HTTP 400, an incompatible prior install (`73`) maps to HTTP 409, and every boundary, Docker,
timeout, output, or unexpected-exit failure maps to HTTP 503. Secret request buffers and captured
process output are zeroed; stderr is never returned.

`POST /sandboxes/:sandboxId/terminalx-supervisor-relay` accepts a single length-prefixed request
frame of at most 1 MiB plus its four-byte prefix and streams framed responses with content type
`application/vnd.terminalx.supervisor-framed`. It executes only the fixed relay as root. The
assignment-installed response is deliberately not readiness evidence: TerminalX admits no
terminal work until a separate signed `isolation.attest` exchange proves the live supervisor and
exact assignment binding through this relay. Before every relay invocation, the runner re-reads
the protected installed assignment, runs the digest-pinned isolation probe, revalidates the
private runner bridge, and prepends at most 256 KiB of fresh canonical Ed25519-signed isolation
evidence. The external caller cannot supply, replace, or omit that evidence. Relay streams inherit
the authenticated caller's connection lifetime; the probe and other fixed preflight operations
retain independent short deadlines and bounded per-Sandbox/global admission.

The signed bootstrap isolation object carries `expectedRunnerBinaryDigest`, which must equal the
digest measured from the live runner before the runner will install the assignment. The in-Sandbox
supervisor independently compares that bootstrap expectation with the signed evidence claim's
`runnerBinaryDigest`; matching only at the host control plane is not sufficient readiness proof.

## Enforced v1 boundary

The runner rejects GPU/Android/device workloads, linked Sandboxes, host or shared volumes,
entrypoint overrides, environment/OTEL injection, skipped startup, resource resizing/recovery,
generic image pull/tag/push/removal or builds, Docker-commit snapshots, and generic backups. These are closed
because they could copy root-owned per-assignment signing material into an image or registry.
Hardened HTTP routing also omits the generic Daytona toolbox proxy entirely, so an agent cannot
bind the now-unused port `2280` and turn the authenticated runner into an unaudited HTTP or
WebSocket bridge around the root supervisor.

Containers are non-privileged, drop all ambient capabilities, add back only the root init's
`CHOWN`, `KILL`, `SETGID`, and `SETUID` capabilities, and set `no-new-privileges`. Each Sandbox has
finite CPU, memory/swap, XFS overlay storage, and a 256-PID cgroup ceiling. It has no external bind,
mount, linked network, port publication, or device request. Create requests are capped at 64 CPUs,
512 GiB memory, and 4096 GiB disk so integer overflow cannot turn a finite request into an
unbounded Docker limit. IPC and cgroup namespaces are explicitly private; healthchecks, tmpfs,
container logging, shared namespace modes, and daemon-dependent security defaults are rejected.
Every hardened container has the fixed hostname `terminalx-sandbox`; the provider Sandbox UUID is
never used as a hostname. The exact UUID remains only in the three-entry, privileged bootstrap
environment so the root-owned init and runner can bind evidence to the real provider resource.
Collaborative PTYs are created through the explicit sanitized-environment daemon path and inherit
only the fixed TerminalX user, shell, locale, path, working-directory, and terminal variables—not
the daemon environment or request-supplied additions.

The root init creates `/run/terminalx-private` as root-only mode `0700`, binds
`daytona-daemon.sock` there as mode `0600`, and passes that already-listening Unix socket to the
Daytona daemon as inherited descriptor 3. Hardened daemon mode is selected only by the exact,
exclusive `--terminalx-toolbox-listener-fd=3` argument. It verifies the descriptor is a listening
Unix socket at the fixed path, disables process dumpability, and opens no TCP toolbox, terminal,
recording-dashboard, or SSH listener. Its private router exposes only the fixed native PTY
operations used by the root supervisor; the general file, command, proxy, port, Git, LSP,
computer-use, and initialization APIs remain absent. The daemon starts with a freshly constructed
public environment containing only the fixed logical ID `terminalx-sandbox`; the real provider
UUID, snapshot reference, bootstrap user, and future root-only values are never inherited by the
same-uid process or its PTY children.

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
