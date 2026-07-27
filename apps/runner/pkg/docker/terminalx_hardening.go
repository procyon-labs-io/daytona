// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/daytonaio/runner/pkg/api/dto"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/strslice"
)

var terminalXSha256ImageID = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var terminalXSha256Raw = regexp.MustCompile(`^[0-9a-f]{64}$`)
var terminalXContainerID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var terminalXSnapshotRef = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,446}@sha256:[0-9a-f]{64}$`)

type terminalXRunnerRequirements struct {
	imageID                          string
	snapshotRef                      string
	resourceLimitsDisabled           bool
	useSnapshotEntrypoint            bool
	interSandboxNetworkEnabled       bool
	containerNetwork                 string
	containerRuntime                 string
	defaultRuntime                   string
	cgroupVersion                    string
	gpuEnabled                       bool
	mountKvm                         bool
	initializeDaemonTelemetry        bool
	networkEnforcementAvailable      bool
	storageDriver                    string
	backingFilesystem                string
	securityOptions                  []string
	expectedDockerServerVersion      string
	actualDockerServerVersion        string
	expectedContainerdCommit         string
	actualContainerdCommit           string
	expectedRuncCommit               string
	actualRuncCommit                 string
	memoryLimitAvailable             bool
	swapLimitAvailable               bool
	cpuQuotaAvailable                bool
	pidsLimitAvailable               bool
	oomKillAvailable                 bool
	liveRestoreEnabled               bool
	supervisorRelaySHA256            string
	assignmentBootstrapSHA256        string
	nodeSHA256                       string
	deploymentBindingInstallerSHA256 string
	isolationProbeSHA256             string
}

const (
	terminalXHardenedProfileLabel                        = "io.terminalx.sandbox.profile"
	terminalXHardenedProfileVersion                      = "v1"
	terminalXHardenedHostname                            = "terminalx-sandbox"
	terminalXHardenedEntrypoint                          = "/usr/local/bin/terminalx-sandbox-init"
	terminalXSandboxUser                                 = "terminalx"
	terminalXSandboxPidsLimit                      int64 = 256
	terminalXSandboxMaxCPU                         int64 = 64
	terminalXSandboxMaxMemoryGiB                   int64 = 512
	terminalXSandboxMaxDiskGiB                     int64 = 4096
	terminalXNetworkProfileLabel                         = "io.terminalx.runner-network"
	terminalXSandboxShmSize                        int64 = 64 * 1024 * 1024
	terminalXSupervisorRelayPath                         = "/usr/local/libexec/terminalx/terminalx-supervisor-relay"
	terminalXSupervisorRelayDigestLabel                  = "io.terminalx.supervisor-relay.sha256"
	terminalXAssignmentBootstrapPath                     = "/usr/local/libexec/terminalx/terminalx-assignment-bootstrap"
	terminalXAssignmentBootstrapDigestLabel              = "io.terminalx.assignment-bootstrap.sha256"
	terminalXNodePath                                    = "/usr/local/bin/node"
	terminalXNodeDigestLabel                             = "io.terminalx.node.sha256"
	terminalXDeploymentBindingInstallerPath              = "/usr/local/libexec/terminalx/terminalx-deployment-binding-install"
	terminalXDeploymentBindingInstallerDigestLabel       = "io.terminalx.deployment-binding-installer.sha256"
	terminalXIsolationProbePath                          = "/usr/local/libexec/terminalx/terminalx-isolation-probe"
	terminalXIsolationProbeDigestLabel                   = "io.terminalx.isolation-probe.sha256"
	terminalXSandboxArtifactDigestLabel                  = "terminalx.artifact"
	terminalXSandboxRevisionLabel                        = "terminalx.revision"
	terminalXSandboxPlanDigestLabel                      = "terminalx.plan"
)

var terminalXMaskedPaths = []string{
	"/proc/asound",
	"/proc/acpi",
	"/proc/interrupts",
	"/proc/kcore",
	"/proc/keys",
	"/proc/latency_stats",
	"/proc/timer_list",
	"/proc/timer_stats",
	"/proc/sched_debug",
	"/proc/scsi",
	"/sys/firmware",
	"/sys/devices/virtual/powercap",
}

var terminalXReadonlyPaths = []string{
	"/proc/bus",
	"/proc/fs",
	"/proc/irq",
	"/proc/sys",
	"/proc/sysrq-trigger",
}

// validateTerminalXCreateRequest rejects every Daytona feature that would
// widen the immutable production Sandbox boundary.  The public API remains
// unchanged, but a dedicated hardened runner is intentionally unable to host
// general-purpose Daytona Sandboxes.
func validateTerminalXCreateRequest(sandboxDto dto.CreateSandboxDTO) error {
	if !terminalXProviderSandboxUUID.MatchString(sandboxDto.Id) {
		return fmt.Errorf("terminalx hardened sandbox identity must be a lowercase UUIDv4")
	}
	if sandboxDto.OsUser != terminalXSandboxUser {
		return fmt.Errorf("terminalx hardened sandbox requires the pinned non-root user")
	}
	if sandboxDto.IsAndroidSandbox() || sandboxDto.GpuQuota != 0 {
		return fmt.Errorf("terminalx hardened sandbox does not permit device passthrough")
	}
	if sandboxDto.FromVolumeId != "" || len(sandboxDto.Volumes) != 0 {
		return fmt.Errorf("terminalx hardened sandbox does not permit shared volumes")
	}
	if sandboxDto.LinkedSandboxId != nil && *sandboxDto.LinkedSandboxId != "" {
		return fmt.Errorf("terminalx hardened sandbox does not permit linked sandboxes")
	}
	if len(sandboxDto.Entrypoint) != 0 &&
		(len(sandboxDto.Entrypoint) != 1 || sandboxDto.Entrypoint[0] != terminalXHardenedEntrypoint) {
		return fmt.Errorf("terminalx hardened sandbox entrypoint is immutable")
	}
	if len(sandboxDto.Env) != 0 {
		return fmt.Errorf("terminalx hardened sandbox does not accept injected environment data")
	}
	if sandboxDto.SandboxClass != nil && *sandboxDto.SandboxClass != "container" {
		return fmt.Errorf("terminalx hardened sandbox class is immutable")
	}
	if sandboxDto.SkipStart != nil && *sandboxDto.SkipStart {
		return fmt.Errorf("terminalx hardened sandbox cannot bypass startup enforcement")
	}
	if sandboxDto.NetworkBlockAll == nil || !*sandboxDto.NetworkBlockAll {
		return fmt.Errorf("terminalx hardened sandbox requires default-deny egress")
	}
	if sandboxDto.NetworkAllowList != nil && strings.TrimSpace(*sandboxDto.NetworkAllowList) != "" {
		return fmt.Errorf("terminalx hardened sandbox does not permit direct egress")
	}
	if sandboxDto.DomainAllowList != nil && strings.TrimSpace(*sandboxDto.DomainAllowList) != "" {
		return fmt.Errorf("terminalx hardened sandbox does not permit direct egress")
	}
	if sandboxDto.CpuQuota < 1 || sandboxDto.CpuQuota > terminalXSandboxMaxCPU ||
		sandboxDto.MemoryQuota < 1 || sandboxDto.MemoryQuota > terminalXSandboxMaxMemoryGiB ||
		sandboxDto.StorageQuota < 1 || sandboxDto.StorageQuota > terminalXSandboxMaxDiskGiB {
		return fmt.Errorf("terminalx hardened sandbox requires finite resources")
	}
	if _, _, _, ok := terminalXCreateBindingFromMetadata(sandboxDto.Metadata); !ok {
		return fmt.Errorf("terminalx hardened sandbox requires an exact immutable logical binding")
	}
	return nil
}

func validateTerminalXSnapshotReference(sandboxDto dto.CreateSandboxDTO, expectedSnapshotRef string) error {
	if !terminalXSnapshotRef.MatchString(expectedSnapshotRef) || sandboxDto.Snapshot != expectedSnapshotRef {
		return fmt.Errorf("terminalx hardened sandbox requires the exact pinned image reference")
	}
	return nil
}

func isSha256ImageID(value string) bool {
	return terminalXSha256ImageID.MatchString(value)
}

func hasTerminalXSeccomp(options []string) bool {
	for _, option := range options {
		if option == "name=seccomp,profile=builtin" {
			return true
		}
	}
	return false
}

func validateTerminalXRunnerRequirements(input terminalXRunnerRequirements) error {
	if !isSha256ImageID(input.imageID) {
		return fmt.Errorf("terminalx hardened runner requires an exact sandbox image id")
	}
	if !terminalXSnapshotRef.MatchString(input.snapshotRef) {
		return fmt.Errorf("terminalx hardened runner requires an exact sandbox snapshot reference")
	}
	if input.resourceLimitsDisabled {
		return fmt.Errorf("terminalx hardened runner requires resource limits")
	}
	if !input.useSnapshotEntrypoint {
		return fmt.Errorf("terminalx hardened runner requires snapshot entrypoints")
	}
	if input.interSandboxNetworkEnabled {
		return fmt.Errorf("terminalx hardened runner requires inter-sandbox networking to be disabled")
	}
	if input.containerNetwork != "" {
		return fmt.Errorf("terminalx hardened runner does not permit an additional container network")
	}
	if input.containerRuntime != "" || input.defaultRuntime != "runc" {
		return fmt.Errorf("terminalx hardened runner requires the docker-default runc runtime")
	}
	if input.cgroupVersion != "2" {
		return fmt.Errorf("terminalx hardened runner requires cgroup v2")
	}
	if input.gpuEnabled || input.mountKvm {
		return fmt.Errorf("terminalx hardened runner does not permit device passthrough")
	}
	if input.initializeDaemonTelemetry {
		return fmt.Errorf("terminalx hardened runner does not inject provider tokens into the sandbox daemon")
	}
	if !input.networkEnforcementAvailable {
		return fmt.Errorf("terminalx hardened runner requires network enforcement")
	}
	if input.storageDriver != "overlay2" || input.backingFilesystem != "xfs" {
		return fmt.Errorf("terminalx hardened runner requires overlay2 xfs project quotas")
	}
	if !hasTerminalXSeccomp(input.securityOptions) {
		return fmt.Errorf("terminalx hardened runner requires the docker seccomp profile")
	}
	if input.expectedDockerServerVersion == "" ||
		input.actualDockerServerVersion != input.expectedDockerServerVersion {
		return fmt.Errorf("terminalx hardened runner requires the pinned docker server version")
	}
	if input.expectedContainerdCommit == "" || input.actualContainerdCommit != input.expectedContainerdCommit {
		return fmt.Errorf("terminalx hardened runner requires the pinned containerd build")
	}
	if input.expectedRuncCommit == "" || input.actualRuncCommit != input.expectedRuncCommit {
		return fmt.Errorf("terminalx hardened runner requires the pinned runc build")
	}
	if !input.memoryLimitAvailable || !input.swapLimitAvailable || !input.cpuQuotaAvailable ||
		!input.pidsLimitAvailable || !input.oomKillAvailable {
		return fmt.Errorf("terminalx hardened runner resource enforcement is incomplete")
	}
	if input.liveRestoreEnabled {
		return fmt.Errorf("terminalx hardened runner does not permit live-restore")
	}
	if !terminalXSha256Raw.MatchString(input.supervisorRelaySHA256) {
		return fmt.Errorf("terminalx hardened runner requires the pinned supervisor relay")
	}
	if !terminalXSha256Raw.MatchString(input.assignmentBootstrapSHA256) {
		return fmt.Errorf("terminalx hardened runner requires the pinned assignment bootstrap")
	}
	if !terminalXSha256Raw.MatchString(input.nodeSHA256) {
		return fmt.Errorf("terminalx hardened runner requires the pinned node interpreter")
	}
	if !terminalXSha256Raw.MatchString(input.deploymentBindingInstallerSHA256) ||
		!terminalXSha256Raw.MatchString(input.isolationProbeSHA256) {
		return fmt.Errorf("terminalx hardened runner requires pinned evidence helpers")
	}
	return nil
}

func validateTerminalXRunnerNetwork(inspected network.Inspect) error {
	if inspected.Name != RUNNER_BRIDGE_NETWORK_NAME || inspected.Driver != "bridge" ||
		inspected.Scope != "local" || !inspected.EnableIPv4 || !inspected.Internal ||
		inspected.EnableIPv6 || inspected.Attachable || inspected.Ingress ||
		inspected.ConfigOnly || inspected.Options["com.docker.network.bridge.enable_icc"] != "false" ||
		inspected.Labels[terminalXNetworkProfileLabel] != terminalXHardenedProfileVersion ||
		inspected.IPAM.Driver != "default" || len(inspected.IPAM.Config) != 1 ||
		inspected.IPAM.Config[0].Subnet != "172.20.0.0/16" {
		return fmt.Errorf("terminalx hardened runner network does not match")
	}
	return nil
}

func validateTerminalXImage(inspected *image.InspectResponse, expectedImageID string) error {
	if inspected == nil || inspected.Config == nil {
		return fmt.Errorf("terminalx hardened sandbox image is unavailable")
	}
	if !isSha256ImageID(expectedImageID) || inspected.ID != expectedImageID {
		return fmt.Errorf("terminalx hardened sandbox image id does not match")
	}
	if inspected.Config.Labels[terminalXHardenedProfileLabel] != terminalXHardenedProfileVersion {
		return fmt.Errorf("terminalx hardened sandbox image profile is not pinned")
	}
	if len(inspected.Config.Volumes) != 0 {
		return fmt.Errorf("terminalx hardened sandbox image declares volumes")
	}
	if inspected.Config.Healthcheck != nil || len(inspected.Config.Cmd) != 0 || len(inspected.Config.ExposedPorts) != 0 {
		return fmt.Errorf("terminalx hardened sandbox image declares an executable side channel")
	}
	if len(inspected.Config.Entrypoint) != 1 || inspected.Config.Entrypoint[0] != terminalXHardenedEntrypoint {
		return fmt.Errorf("terminalx hardened sandbox image entrypoint is not pinned")
	}
	if inspected.Config.User != "" && inspected.Config.User != "0" && inspected.Config.User != "root" {
		return fmt.Errorf("terminalx hardened sandbox init must start with supervisor privileges")
	}
	return nil
}

func validateTerminalXSupervisorRelayLabel(labels map[string]string, expectedSHA256 string) error {
	if !terminalXSha256Raw.MatchString(expectedSHA256) || labels[terminalXSupervisorRelayDigestLabel] != expectedSHA256 {
		return fmt.Errorf("terminalx hardened supervisor relay digest does not match")
	}
	return nil
}

func validateTerminalXAssignmentBootstrapLabel(labels map[string]string, expectedSHA256 string) error {
	if !terminalXSha256Raw.MatchString(expectedSHA256) || labels[terminalXAssignmentBootstrapDigestLabel] != expectedSHA256 {
		return fmt.Errorf("terminalx hardened assignment bootstrap digest does not match")
	}
	return nil
}

func validateTerminalXNodeLabel(labels map[string]string, expectedSHA256 string) error {
	if !terminalXSha256Raw.MatchString(expectedSHA256) || labels[terminalXNodeDigestLabel] != expectedSHA256 {
		return fmt.Errorf("terminalx hardened node interpreter digest does not match")
	}
	return nil
}

func validateTerminalXEvidenceHelperLabels(labels map[string]string, installerSHA256 string, probeSHA256 string) error {
	if !terminalXSha256Raw.MatchString(installerSHA256) ||
		labels[terminalXDeploymentBindingInstallerDigestLabel] != installerSHA256 ||
		!terminalXSha256Raw.MatchString(probeSHA256) ||
		labels[terminalXIsolationProbeDigestLabel] != probeSHA256 {
		return fmt.Errorf("terminalx hardened evidence helper digests do not match")
	}
	return nil
}

func (d *DockerClient) validateTerminalXImageArtifact(inspected *image.InspectResponse) error {
	if err := validateTerminalXImage(inspected, d.terminalXSandboxImageID); err != nil {
		return err
	}
	if err := validateTerminalXSupervisorRelayLabel(inspected.Config.Labels, d.terminalXSupervisorRelaySHA256); err != nil {
		return err
	}
	if err := validateTerminalXAssignmentBootstrapLabel(inspected.Config.Labels, d.terminalXAssignmentBootstrapSHA256); err != nil {
		return err
	}
	if err := validateTerminalXNodeLabel(inspected.Config.Labels, d.terminalXNodeSHA256); err != nil {
		return err
	}
	return validateTerminalXEvidenceHelperLabels(
		inspected.Config.Labels,
		d.terminalXDeploymentBindingInstallerSHA256,
		d.terminalXIsolationProbeSHA256,
	)
}

func (d *DockerClient) terminalXHostConfig(sandboxDto dto.CreateSandboxDTO, volumeMountPathBinds []string, gpuIndex *int) (*container.HostConfig, error) {
	if err := validateTerminalXCreateRequest(sandboxDto); err != nil {
		return nil, err
	}
	if len(volumeMountPathBinds) != 0 || gpuIndex != nil {
		return nil, fmt.Errorf("terminalx hardened sandbox mount or device request is invalid")
	}
	if d.resourceLimitsDisabled || d.filesystem != "xfs" {
		return nil, fmt.Errorf("terminalx hardened sandbox resource enforcement is unavailable")
	}

	pidsLimit := terminalXSandboxPidsLimit
	memorySwappiness := int64(0)
	oomKillDisable := false
	initProcess := true
	return &container.HostConfig{
		Privileged:   false,
		NetworkMode:  container.NetworkMode(RUNNER_BRIDGE_NETWORK_NAME),
		CapDrop:      strslice.StrSlice{"ALL"},
		IpcMode:      container.IPCModePrivate,
		CgroupnsMode: container.CgroupnsModePrivate,
		Init:         &initProcess,
		LogConfig: container.LogConfig{
			Type: "none",
		},
		ShmSize:       terminalXSandboxShmSize,
		MaskedPaths:   append([]string(nil), terminalXMaskedPaths...),
		ReadonlyPaths: append([]string(nil), terminalXReadonlyPaths...),
		// The root-owned init needs only enough privilege to create and stop the
		// non-root daemon process.  The init must clear these capabilities when
		// it changes to the terminalx uid; effective agent capability checks are
		// part of the signed isolation attestation.
		CapAdd:      strslice.StrSlice{"CHOWN", "KILL", "SETGID", "SETUID"},
		SecurityOpt: []string{"no-new-privileges:true"},
		Resources: container.Resources{
			CPUPeriod:        100000,
			CPUQuota:         sandboxDto.CpuQuota * 100000,
			Memory:           commonGBToBytes(sandboxDto.MemoryQuota),
			MemorySwap:       commonGBToBytes(sandboxDto.MemoryQuota),
			MemorySwappiness: &memorySwappiness,
			OomKillDisable:   &oomKillDisable,
			PidsLimit:        &pidsLimit,
		},
		StorageOpt: map[string]string{
			"size": fmt.Sprintf("%dG", sandboxDto.StorageQuota),
		},
	}, nil
}

// commonGBToBytes keeps the hardened HostConfig construction pure and makes
// the exact integer conversion visible to focused tests.
func commonGBToBytes(gib int64) int64 {
	return gib * 1024 * 1024 * 1024
}

func (d *DockerClient) requireTerminalXContainer(containerInfo *container.InspectResponse) error {
	if containerInfo == nil || containerInfo.Config == nil || containerInfo.HostConfig == nil {
		return fmt.Errorf("terminalx hardened sandbox inspection is unavailable")
	}
	if containerInfo.Image != d.terminalXSandboxImageID ||
		!terminalXContainerID.MatchString(containerInfo.ID) ||
		containerInfo.Config.Labels[terminalXHardenedProfileLabel] != terminalXHardenedProfileVersion ||
		containerInfo.Config.Labels[terminalXSupervisorRelayDigestLabel] != d.terminalXSupervisorRelaySHA256 ||
		containerInfo.Config.Labels[terminalXAssignmentBootstrapDigestLabel] != d.terminalXAssignmentBootstrapSHA256 ||
		containerInfo.Config.Labels[terminalXNodeDigestLabel] != d.terminalXNodeSHA256 ||
		containerInfo.Config.Labels[terminalXDeploymentBindingInstallerDigestLabel] != d.terminalXDeploymentBindingInstallerSHA256 ||
		containerInfo.Config.Labels[terminalXIsolationProbeDigestLabel] != d.terminalXIsolationProbeSHA256 ||
		containerInfo.Config.Labels[terminalXSandboxArtifactDigestLabel] != d.terminalXSandboxArtifactDigest ||
		!validTerminalXSandboxRevision(containerInfo.Config.Labels[terminalXSandboxRevisionLabel]) ||
		!terminalXSha256Raw.MatchString(containerInfo.Config.Labels[terminalXSandboxPlanDigestLabel]) ||
		len(containerInfo.Config.Entrypoint) != 1 ||
		containerInfo.Config.Entrypoint[0] != terminalXHardenedEntrypoint ||
		len(containerInfo.Config.Volumes) != 0 ||
		(containerInfo.Config.User != "" && containerInfo.Config.User != "0" && containerInfo.Config.User != "root") ||
		containerInfo.Config.Healthcheck != nil || len(containerInfo.Config.Cmd) != 0 ||
		len(containerInfo.Config.ExposedPorts) != 0 || containerInfo.Config.Domainname != "" ||
		containerInfo.Config.OpenStdin || containerInfo.Config.StdinOnce || containerInfo.Config.Tty ||
		containerInfo.Config.NetworkDisabled || containerInfo.Config.MacAddress != "" ||
		len(containerInfo.Config.OnBuild) != 0 {
		return fmt.Errorf("terminalx hardened sandbox profile does not match")
	}
	if !validTerminalXContainerEnvironment(containerInfo.Config.Env, containerInfo.Config.Hostname, d.terminalXSandboxSnapshotRef) {
		return fmt.Errorf("terminalx hardened sandbox environment does not match")
	}
	host := containerInfo.HostConfig
	if host.Privileged || host.ReadonlyRootfs || len(host.Binds) != 0 || len(host.Mounts) != 0 ||
		len(containerInfo.Mounts) != 0 ||
		len(host.VolumesFrom) != 0 || len(host.Devices) != 0 || len(host.DeviceRequests) != 0 ||
		len(host.DeviceCgroupRules) != 0 || len(host.ExtraHosts) != 0 ||
		len(host.PortBindings) != 0 || host.PublishAllPorts || len(host.Links) != 0 ||
		len(host.GroupAdd) != 0 || len(host.Sysctls) != 0 || len(host.Ulimits) != 0 ||
		len(host.DNS) != 0 || len(host.DNSOptions) != 0 || len(host.DNSSearch) != 0 ||
		len(host.Tmpfs) != 0 || host.Cgroup != "" || host.UsernsMode != "" ||
		host.ContainerIDFile != "" || host.VolumeDriver != "" || len(host.Annotations) != 0 ||
		host.ConsoleSize != [2]uint{} || host.OomScoreAdj != 0 || host.AutoRemove ||
		(host.RestartPolicy.Name != "" && host.RestartPolicy.Name != "no") || host.PidMode != "" ||
		host.IpcMode != container.IPCModePrivate || host.UTSMode != "" ||
		host.CgroupnsMode != container.CgroupnsModePrivate ||
		host.NetworkMode != container.NetworkMode(RUNNER_BRIDGE_NETWORK_NAME) ||
		(host.Runtime != "" && host.Runtime != "runc") ||
		host.Init == nil || !*host.Init || host.LogConfig.Type != "none" || len(host.LogConfig.Config) != 0 ||
		host.ShmSize != terminalXSandboxShmSize || !slices.Equal(host.MaskedPaths, terminalXMaskedPaths) ||
		!slices.Equal(host.ReadonlyPaths, terminalXReadonlyPaths) {
		return fmt.Errorf("terminalx hardened sandbox mount isolation does not match")
	}
	if !terminalXFiniteResourcesMatch(host) {
		return fmt.Errorf("terminalx hardened sandbox process limit does not match")
	}
	if len(host.CapDrop) != 1 || !containsFold([]string(host.CapDrop), "ALL") ||
		!sameTerminalXCapabilities([]string(host.CapAdd)) ||
		len(host.SecurityOpt) != 1 || !containsFold(host.SecurityOpt, "no-new-privileges:true") {
		return fmt.Errorf("terminalx hardened sandbox privilege controls do not match")
	}
	if containerInfo.NetworkSettings == nil || len(containerInfo.NetworkSettings.Networks) != 1 {
		return fmt.Errorf("terminalx hardened sandbox network attachment does not match")
	}
	endpoint := containerInfo.NetworkSettings.Networks[RUNNER_BRIDGE_NETWORK_NAME]
	if endpoint == nil {
		return fmt.Errorf("terminalx hardened sandbox network attachment does not match")
	}
	endpointIP := endpoint.IPAddress
	if endpointIP == "" && endpoint.IPAMConfig != nil {
		endpointIP = endpoint.IPAMConfig.IPv4Address
	}
	address, err := netip.ParseAddr(endpointIP)
	if err != nil || !netip.MustParsePrefix("172.20.0.0/16").Contains(address) {
		return fmt.Errorf("terminalx hardened sandbox network address does not match")
	}
	return nil
}

func terminalXFiniteResourcesMatch(host *container.HostConfig) bool {
	{
		sw := "nil"; if host.MemorySwappiness != nil { sw = fmt.Sprintf("%d", *host.MemorySwappiness) }
		ok := "nil"; if host.OomKillDisable != nil { ok = fmt.Sprintf("%v", *host.OomKillDisable) }
		pl := "nil"; if host.PidsLimit != nil { pl = fmt.Sprintf("%d", *host.PidsLimit) }
		fmt.Fprintf(os.Stderr, "[plim] period=%d quota=%d mem=%d swap=%d swpns=%s oom=%s pids=%s cpuset=%q memres=%d kmem=%d kmemtcp=%d storage=%v shares=%d nano=%d count=%d pct=%d blkio=%d rtp=%d rtr=%d cgparent=%q\n",
			host.CPUPeriod, host.CPUQuota, host.Memory, host.MemorySwap, sw, ok, pl, host.CpusetCpus, host.MemoryReservation, host.KernelMemory, host.KernelMemoryTCP, host.StorageOpt, host.CPUShares, host.NanoCPUs, host.CPUCount, host.CPUPercent, host.BlkioWeight, host.CPURealtimePeriod, host.CPURealtimeRuntime, host.CgroupParent)
	}
	if host.PidsLimit == nil || *host.PidsLimit != terminalXSandboxPidsLimit ||
		host.CPUShares != 0 || host.NanoCPUs != 0 || host.CgroupParent != "" ||
		host.BlkioWeight != 0 || len(host.BlkioWeightDevice) != 0 ||
		len(host.BlkioDeviceReadBps) != 0 || len(host.BlkioDeviceWriteBps) != 0 ||
		len(host.BlkioDeviceReadIOps) != 0 || len(host.BlkioDeviceWriteIOps) != 0 ||
		host.CPUPeriod != 100000 || host.CPUQuota < 100000 ||
		host.CPUQuota > terminalXSandboxMaxCPU*100000 || host.CPUQuota%100000 != 0 ||
		host.CPURealtimePeriod != 0 || host.CPURealtimeRuntime != 0 ||
		host.CpusetCpus != "" || host.CpusetMems != "" ||
		host.Memory < commonGBToBytes(1) || host.Memory > commonGBToBytes(terminalXSandboxMaxMemoryGiB) ||
		host.Memory%commonGBToBytes(1) != 0 || host.MemorySwap != host.Memory ||
		host.KernelMemory != 0 || host.KernelMemoryTCP != 0 || host.MemoryReservation != 0 ||
		(host.MemorySwappiness != nil && *host.MemorySwappiness != 0) ||
		host.OomKillDisable == nil || *host.OomKillDisable || host.CPUCount != 0 ||
		host.CPUPercent != 0 || host.IOMaximumIOps != 0 || host.IOMaximumBandwidth != 0 ||
		len(host.StorageOpt) != 1 {
		return false
	}
	storage := host.StorageOpt["size"]
	if !strings.HasSuffix(storage, "G") {
		return false
	}
	diskGiB, err := strconv.ParseInt(strings.TrimSuffix(storage, "G"), 10, 64)
	return err == nil && diskGiB >= 1 && diskGiB <= terminalXSandboxMaxDiskGiB &&
		storage == strconv.FormatInt(diskGiB, 10)+"G"
}

func terminalXProviderSandboxIDFromEnvironment(values []string, imageID string) (string, bool) {
	if len(values) != 3 {
		return "", false
	}
	environment := make(map[string]string, len(values))
	for _, value := range values {
		key, actual, ok := strings.Cut(value, "=")
		if !ok {
			return "", false
		}
		switch key {
		case "DAYTONA_SANDBOX_ID", "DAYTONA_SANDBOX_SNAPSHOT", "DAYTONA_SANDBOX_USER":
		default:
			return "", false
		}
		if _, duplicate := environment[key]; duplicate {
			return "", false
		}
		environment[key] = actual
	}
	providerSandboxID := environment["DAYTONA_SANDBOX_ID"]
	if !terminalXProviderSandboxUUID.MatchString(providerSandboxID) ||
		environment["DAYTONA_SANDBOX_SNAPSHOT"] != imageID ||
		environment["DAYTONA_SANDBOX_USER"] != terminalXSandboxUser {
		return "", false
	}
	return providerSandboxID, true
}

func validTerminalXContainerEnvironment(values []string, hostname string, imageID string) bool {
	if hostname != terminalXHardenedHostname {
		return false
	}
	_, ok := terminalXProviderSandboxIDFromEnvironment(values, imageID)
	return ok
}

func terminalXCreateBindingFromMetadata(metadata map[string]string) (artifactDigest string, revision string, planDigest string, ok bool) {
	if len(metadata) != 3 {
		return "", "", "", false
	}
	artifactDigest = metadata[terminalXSandboxArtifactDigestLabel]
	revision = metadata[terminalXSandboxRevisionLabel]
	planDigest = metadata[terminalXSandboxPlanDigestLabel]
	if !terminalXSha256Raw.MatchString(artifactDigest) || !validTerminalXSandboxRevision(revision) ||
		!terminalXSha256Raw.MatchString(planDigest) {
		return "", "", "", false
	}
	return artifactDigest, revision, planDigest, true
}

func validTerminalXSandboxRevision(value string) bool {
	revision, err := strconv.ParseUint(value, 10, 53)
	return err == nil && revision >= 1 && revision <= terminalXJavaScriptMaximumSafeInteger &&
		value == strconv.FormatUint(revision, 10)
}

func sameTerminalXCapabilities(values []string) bool {
	if len(values) != 4 {
		return false
	}
	want := map[string]bool{"CHOWN": true, "KILL": true, "SETGID": true, "SETUID": true}
	for _, value := range values {
		value = strings.TrimPrefix(strings.ToUpper(value), "CAP_")
		if !want[value] {
			return false
		}
		delete(want, value)
	}
	return len(want) == 0
}

func containsFold(values []string, expected string) bool {
	for _, value := range values {
		if strings.EqualFold(value, expected) {
			return true
		}
	}
	return false
}

// enforceTerminalXNetworkPolicy installs and assigns the DROP chain before
// ContainerStart.  This avoids the historical post-start window in which a
// Sandbox process could reach the network before asynchronous iptables work.
func terminalXSandboxIPv4(sandboxID string) string {
	sum := sha256.Sum256([]byte("terminalx/sandbox-ipv4/v1\x00" + sandboxID))
	return fmt.Sprintf("172.20.%d.%d", int(sum[0]), 2+int(sum[1])%252)
}

func (d *DockerClient) enforceTerminalXNetworkPolicy(ctx context.Context, containerInfo *container.InspectResponse) error {
	if err := d.requireTerminalXContainer(containerInfo); err != nil {
		return err
	}
	if len(containerInfo.ID) < 12 {
		return fmt.Errorf("terminalx hardened sandbox identity is invalid")
	}
	ip := GetContainerIpAddress(ctx, containerInfo)
	if ip == "" {
		if ep := containerInfo.NetworkSettings.Networks[RUNNER_BRIDGE_NETWORK_NAME]; ep != nil && ep.IPAMConfig != nil {
			ip = ep.IPAMConfig.IPv4Address
		}
	}
	if ip == "" {
		return fmt.Errorf("terminalx hardened sandbox network identity is unavailable")
	}
	if d.netRulesManager == nil {
		return fmt.Errorf("terminalx hardened sandbox network enforcement is unavailable")
	}
	return d.netRulesManager.SetBlockedNetworkRules(containerInfo.ID[:12], ip)
}

func (d *DockerClient) reconcileTerminalXContainers(ctx context.Context) error {
	preloaded, err := d.apiClient.ImageInspect(ctx, d.terminalXSandboxSnapshotRef)
	if err != nil {
		return fmt.Errorf("terminalx hardened sandbox image is not preloaded: %w", err)
	}
	if err := d.validateTerminalXImageArtifact(&preloaded); err != nil {
		return err
	}
	containers, err := d.apiClient.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return fmt.Errorf("terminalx hardened runner could not list existing containers: %w", err)
	}
	for _, summary := range containers {
		inspected, err := d.apiClient.ContainerInspect(ctx, summary.ID)
		if err != nil {
			return fmt.Errorf("terminalx hardened runner could not inspect existing container: %w", err)
		}
		if err := d.enforceTerminalXNetworkPolicy(ctx, &inspected); err != nil {
			return err
		}
	}
	return nil
}

// quarantineTerminalXContainers terminates every running workload on the
// dedicated host before returning the boundary failure. A hardened runner is
// single-purpose, so leaving a workload executing after validation or network
// enforcement fails would be a fail-open outcome.
func (d *DockerClient) quarantineTerminalXContainers(ctx context.Context, cause error) error {
	errorsToReturn := []error{cause}
	containers, err := d.apiClient.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		return errors.Join(cause, fmt.Errorf("terminalx hardened runner could not list workloads for quarantine: %w", err))
	}
	for _, summary := range containers {
		if err := d.apiClient.ContainerKill(ctx, summary.ID, "KILL"); err != nil {
			errorsToReturn = append(errorsToReturn,
				fmt.Errorf("terminalx hardened runner could not quarantine container %s: %w", summary.ID, err))
		}
	}
	return errors.Join(errorsToReturn...)
}
