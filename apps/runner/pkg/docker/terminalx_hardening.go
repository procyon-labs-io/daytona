// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
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
var terminalXSnapshotRef = regexp.MustCompile(`^[^\x00-\x20\x7f]{1,300}$`)

type terminalXRunnerRequirements struct {
	imageID                     string
	snapshotRef                 string
	resourceLimitsDisabled      bool
	useSnapshotEntrypoint       bool
	interSandboxNetworkEnabled  bool
	containerNetwork            string
	containerRuntime            string
	defaultRuntime              string
	cgroupVersion               string
	gpuEnabled                  bool
	mountKvm                    bool
	initializeDaemonTelemetry   bool
	networkEnforcementAvailable bool
	storageDriver               string
	backingFilesystem           string
	securityOptions             []string
	expectedDockerServerVersion string
	actualDockerServerVersion   string
	expectedContainerdCommit    string
	actualContainerdCommit      string
	expectedRuncCommit          string
	actualRuncCommit            string
	memoryLimitAvailable        bool
	swapLimitAvailable          bool
	cpuQuotaAvailable           bool
	pidsLimitAvailable          bool
	oomKillAvailable            bool
	liveRestoreEnabled          bool
}

const (
	terminalXHardenedProfileLabel         = "io.terminalx.sandbox.profile"
	terminalXHardenedProfileVersion       = "v1"
	terminalXHardenedEntrypoint           = "/usr/local/bin/terminalx-sandbox-init"
	terminalXSandboxUser                  = "terminalx"
	terminalXSandboxPidsLimit       int64 = 256
	terminalXSandboxMaxCPU          int64 = 64
	terminalXSandboxMaxMemoryGiB    int64 = 512
	terminalXSandboxMaxDiskGiB      int64 = 4096
	terminalXNetworkProfileLabel          = "io.terminalx.runner-network"
	terminalXSandboxShmSize         int64 = 64 * 1024 * 1024
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
		containerInfo.Config.Labels[terminalXHardenedProfileLabel] != terminalXHardenedProfileVersion ||
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
		(host.NetworkMode != "" && host.NetworkMode != "default") ||
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
	address, err := netip.ParseAddr(endpoint.IPAddress)
	if err != nil || !netip.MustParsePrefix("172.20.0.0/16").Contains(address) {
		return fmt.Errorf("terminalx hardened sandbox network address does not match")
	}
	return nil
}

func terminalXFiniteResourcesMatch(host *container.HostConfig) bool {
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
		host.MemorySwappiness == nil || *host.MemorySwappiness != 0 ||
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

func validTerminalXContainerEnvironment(values []string, hostname string, imageID string) bool {
	if hostname == "" || len(values) != 3 {
		return false
	}
	want := map[string]string{
		"DAYTONA_SANDBOX_ID":       hostname,
		"DAYTONA_SANDBOX_SNAPSHOT": imageID,
		"DAYTONA_SANDBOX_USER":     terminalXSandboxUser,
	}
	for _, value := range values {
		key, actual, ok := strings.Cut(value, "=")
		if !ok || want[key] != actual {
			return false
		}
		delete(want, key)
	}
	return len(want) == 0
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
func (d *DockerClient) enforceTerminalXNetworkPolicy(ctx context.Context, containerInfo *container.InspectResponse) error {
	if err := d.requireTerminalXContainer(containerInfo); err != nil {
		return err
	}
	if len(containerInfo.ID) < 12 {
		return fmt.Errorf("terminalx hardened sandbox identity is invalid")
	}
	ip := GetContainerIpAddress(ctx, containerInfo)
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
	if err := validateTerminalXImage(&preloaded, d.terminalXSandboxImageID); err != nil {
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
