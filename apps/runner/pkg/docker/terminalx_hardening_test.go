// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/api/dto"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	dockerspec "github.com/moby/docker-image-spec/specs-go/v1"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const testTerminalXImageID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testTerminalXSnapshotRef = "registry.example/terminalx/sandbox@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
const testTerminalXSupervisorRelaySHA256 = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
const testTerminalXAssignmentBootstrapSHA256 = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
const testTerminalXNodeSHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
const testTerminalXDeploymentBindingInstallerSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
const testTerminalXIsolationProbeSHA256 = "9999999999999999999999999999999999999999999999999999999999999999"
const testTerminalXSandboxUUID = "123e4567-e89b-42d3-a456-426614174000"
const testTerminalXSandboxArtifactDigest = "1111111111111111111111111111111111111111111111111111111111111111"
const testTerminalXSandboxPlanDigest = "2222222222222222222222222222222222222222222222222222222222222222"

func terminalXCreateRequest() dto.CreateSandboxDTO {
	blockAll := true
	return dto.CreateSandboxDTO{
		Id:              testTerminalXSandboxUUID,
		UserId:          "user-1",
		Snapshot:        testTerminalXSnapshotRef,
		OsUser:          terminalXSandboxUser,
		CpuQuota:        2,
		MemoryQuota:     4,
		StorageQuota:    20,
		NetworkBlockAll: &blockAll,
		Metadata: map[string]string{
			terminalXSandboxArtifactDigestLabel: testTerminalXSandboxArtifactDigest,
			terminalXSandboxRevisionLabel:       "1",
			terminalXSandboxPlanDigestLabel:     testTerminalXSandboxPlanDigest,
		},
	}
}

func terminalXImage() *image.InspectResponse {
	return &image.InspectResponse{
		ID: testTerminalXImageID,
		Config: &dockerspec.DockerOCIImageConfig{ImageConfig: ocispec.ImageConfig{
			User:       "root",
			Entrypoint: []string{terminalXHardenedEntrypoint},
			Labels: map[string]string{
				terminalXHardenedProfileLabel:                  terminalXHardenedProfileVersion,
				terminalXSupervisorRelayDigestLabel:            testTerminalXSupervisorRelaySHA256,
				terminalXAssignmentBootstrapDigestLabel:        testTerminalXAssignmentBootstrapSHA256,
				terminalXNodeDigestLabel:                       testTerminalXNodeSHA256,
				terminalXDeploymentBindingInstallerDigestLabel: testTerminalXDeploymentBindingInstallerSHA256,
				terminalXIsolationProbeDigestLabel:             testTerminalXIsolationProbeSHA256,
			},
		}},
	}
}

func terminalXContainerForTest(t *testing.T) (*DockerClient, *container.InspectResponse) {
	t.Helper()
	client := &DockerClient{
		terminalXHardened:                         true,
		terminalXSandboxImageID:                   testTerminalXImageID,
		terminalXSandboxSnapshotRef:               testTerminalXSnapshotRef,
		terminalXSupervisorRelaySHA256:            testTerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapSHA256:        testTerminalXAssignmentBootstrapSHA256,
		terminalXNodeSHA256:                       testTerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerSHA256: testTerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeSHA256:             testTerminalXIsolationProbeSHA256,
		terminalXSandboxArtifactDigest:            testTerminalXSandboxArtifactDigest,
		filesystem:                                "xfs",
	}
	host, err := client.terminalXHostConfig(terminalXCreateRequest(), nil, nil)
	if err != nil {
		t.Fatalf("host config failed: %v", err)
	}
	return client, &container.InspectResponse{
		ContainerJSONBase: &container.ContainerJSONBase{
			ID:         "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			Image:      testTerminalXImageID,
			HostConfig: host,
		},
		Config: &container.Config{
			Hostname: terminalXHardenedHostname,
			Env: []string{
				"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
				"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
				"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
			},
			Entrypoint: []string{terminalXHardenedEntrypoint},
			Labels: map[string]string{
				terminalXHardenedProfileLabel:                  terminalXHardenedProfileVersion,
				terminalXSupervisorRelayDigestLabel:            testTerminalXSupervisorRelaySHA256,
				terminalXAssignmentBootstrapDigestLabel:        testTerminalXAssignmentBootstrapSHA256,
				terminalXNodeDigestLabel:                       testTerminalXNodeSHA256,
				terminalXDeploymentBindingInstallerDigestLabel: testTerminalXDeploymentBindingInstallerSHA256,
				terminalXIsolationProbeDigestLabel:             testTerminalXIsolationProbeSHA256,
				terminalXSandboxArtifactDigestLabel:            testTerminalXSandboxArtifactDigest,
				terminalXSandboxRevisionLabel:                  "1",
				terminalXSandboxPlanDigestLabel:                testTerminalXSandboxPlanDigest,
			},
		},
		NetworkSettings: &container.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				RUNNER_BRIDGE_NETWORK_NAME: {IPAddress: "172.20.0.2"},
			},
		},
	}
}

func TestValidateTerminalXCreateRequestAcceptsExactProfile(t *testing.T) {
	t.Parallel()
	request := terminalXCreateRequest()
	otel := "http://collector.internal:4318"
	organization := "organization-1"
	region := "region-1"
	sandboxClass := "container"
	request.Entrypoint = []string{terminalXHardenedEntrypoint}
	request.OtelEndpoint = &otel
	request.OrganizationId = &organization
	request.RegionId = &region
	request.SandboxClass = &sandboxClass
	request.Registry = &dto.RegistryDTO{}
	if err := validateTerminalXCreateRequest(request); err != nil {
		t.Fatalf("valid hardened request rejected: %v", err)
	}
}

func TestValidateTerminalXCreateRequestRejectsBoundaryWidening(t *testing.T) {
	t.Parallel()
	falseValue := false
	trueValue := true
	linked := "other-sandbox"
	allow := "10.0.0.0/8"
	domain := "example.com"
	sandboxClass := "standard"
	tests := map[string]func(*dto.CreateSandboxDTO){
		"non uuid identity":   func(v *dto.CreateSandboxDTO) { v.Id = "sandbox-1" },
		"uppercase identity":  func(v *dto.CreateSandboxDTO) { v.Id = "123E4567-E89B-42D3-A456-426614174000" },
		"wrong uuid version":  func(v *dto.CreateSandboxDTO) { v.Id = "123e4567-e89b-32d3-a456-426614174000" },
		"root user":           func(v *dto.CreateSandboxDTO) { v.OsUser = "root" },
		"gpu":                 func(v *dto.CreateSandboxDTO) { v.GpuQuota = 1 },
		"volume":              func(v *dto.CreateSandboxDTO) { v.Volumes = []dto.VolumeDTO{{}} },
		"volume restore":      func(v *dto.CreateSandboxDTO) { v.FromVolumeId = "volume-1" },
		"linked sandbox":      func(v *dto.CreateSandboxDTO) { v.LinkedSandboxId = &linked },
		"entrypoint override": func(v *dto.CreateSandboxDTO) { v.Entrypoint = []string{"sh"} },
		"environment":         func(v *dto.CreateSandboxDTO) { v.Env = map[string]string{"TOKEN": "secret"} },
		"sandbox class":       func(v *dto.CreateSandboxDTO) { v.SandboxClass = &sandboxClass },
		"skip start":          func(v *dto.CreateSandboxDTO) { v.SkipStart = &trueValue },
		"missing network":     func(v *dto.CreateSandboxDTO) { v.NetworkBlockAll = nil },
		"open network":        func(v *dto.CreateSandboxDTO) { v.NetworkBlockAll = &falseValue },
		"cidr egress":         func(v *dto.CreateSandboxDTO) { v.NetworkAllowList = &allow },
		"domain egress":       func(v *dto.CreateSandboxDTO) { v.DomainAllowList = &domain },
		"unbounded cpu":       func(v *dto.CreateSandboxDTO) { v.CpuQuota = 0 },
		"unbounded memory":    func(v *dto.CreateSandboxDTO) { v.MemoryQuota = 0 },
		"unbounded disk":      func(v *dto.CreateSandboxDTO) { v.StorageQuota = 0 },
		"excess cpu":          func(v *dto.CreateSandboxDTO) { v.CpuQuota = terminalXSandboxMaxCPU + 1 },
		"excess memory":       func(v *dto.CreateSandboxDTO) { v.MemoryQuota = terminalXSandboxMaxMemoryGiB + 1 },
		"excess disk":         func(v *dto.CreateSandboxDTO) { v.StorageQuota = terminalXSandboxMaxDiskGiB + 1 },
		"missing logical binding": func(v *dto.CreateSandboxDTO) {
			v.Metadata = nil
		},
		"logical binding injection": func(v *dto.CreateSandboxDTO) {
			v.Metadata["organizationId"] = "organization-1"
		},
		"non canonical revision": func(v *dto.CreateSandboxDTO) {
			v.Metadata[terminalXSandboxRevisionLabel] = "01"
		},
		"zero revision": func(v *dto.CreateSandboxDTO) {
			v.Metadata[terminalXSandboxRevisionLabel] = "0"
		},
		"invalid plan digest": func(v *dto.CreateSandboxDTO) {
			v.Metadata[terminalXSandboxPlanDigestLabel] = strings.Repeat("A", 64)
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := terminalXCreateRequest()
			mutate(&request)
			if err := validateTerminalXCreateRequest(request); err == nil {
				t.Fatal("boundary-widening request was accepted")
			}
		})
	}
}

func TestValidateTerminalXSnapshotReferenceRequiresPreloadedPin(t *testing.T) {
	t.Parallel()
	request := terminalXCreateRequest()
	if err := validateTerminalXSnapshotReference(request, testTerminalXSnapshotRef); err != nil {
		t.Fatalf("valid pinned reference rejected: %v", err)
	}
	request.Snapshot = "terminalx/sandbox:latest"
	if err := validateTerminalXSnapshotReference(request, testTerminalXSnapshotRef); err == nil {
		t.Fatal("mutable image reference was accepted")
	}
	request = terminalXCreateRequest()
	request.Registry = &dto.RegistryDTO{}
	if err := validateTerminalXSnapshotReference(request, testTerminalXSnapshotRef); err != nil {
		t.Fatalf("platform registry context was rejected: %v", err)
	}
	if err := validateTerminalXSnapshotReference(request, "bad snapshot ref"); err == nil {
		t.Fatal("unsafe expected snapshot reference was accepted")
	}
}

func TestTerminalXContainerConfigStripsPlatformEnvironment(t *testing.T) {
	t.Parallel()
	otel := "http://collector.internal:4318"
	organization := "organization-1"
	region := "region-1"
	sandboxClass := "container"
	request := terminalXCreateRequest()
	request.OtelEndpoint = &otel
	request.OrganizationId = &organization
	request.RegionId = &region
	request.SandboxClass = &sandboxClass
	request.Registry = &dto.RegistryDTO{}
	request.Entrypoint = []string{terminalXHardenedEntrypoint}
	client := &DockerClient{
		terminalXHardened:                         true,
		terminalXSandboxImageID:                   testTerminalXImageID,
		terminalXSandboxSnapshotRef:               testTerminalXSnapshotRef,
		terminalXSupervisorRelaySHA256:            testTerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapSHA256:        testTerminalXAssignmentBootstrapSHA256,
		terminalXNodeSHA256:                       testTerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerSHA256: testTerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeSHA256:             testTerminalXIsolationProbeSHA256,
		terminalXSandboxArtifactDigest:            testTerminalXSandboxArtifactDigest,
		useSnapshotEntrypoint:                     true,
	}
	config, err := client.getContainerCreateConfig(request, terminalXImage(), nil)
	if err != nil {
		t.Fatalf("hardened container config failed: %v", err)
	}
	if config.Hostname != terminalXHardenedHostname ||
		!validTerminalXContainerEnvironment(config.Env, config.Hostname, testTerminalXSnapshotRef) {
		t.Fatalf("unexpected hardened environment: %v", config.Env)
	}
	providerSandboxID, ok := terminalXProviderSandboxIDFromEnvironment(config.Env, testTerminalXSnapshotRef)
	if !ok || providerSandboxID != request.Id {
		t.Fatalf("provider identity was not preserved in the privileged init environment: %q", providerSandboxID)
	}
	for label, expected := range map[string]string{
		terminalXHardenedProfileLabel:                  terminalXHardenedProfileVersion,
		terminalXSupervisorRelayDigestLabel:            testTerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapDigestLabel:        testTerminalXAssignmentBootstrapSHA256,
		terminalXNodeDigestLabel:                       testTerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerDigestLabel: testTerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeDigestLabel:             testTerminalXIsolationProbeSHA256,
		terminalXSandboxArtifactDigestLabel:            testTerminalXSandboxArtifactDigest,
		terminalXSandboxRevisionLabel:                  "1",
		terminalXSandboxPlanDigestLabel:                testTerminalXSandboxPlanDigest,
	} {
		if config.Labels[label] != expected {
			t.Fatalf("hardened container label %s was not pinned", label)
		}
	}
}

func TestTerminalXProviderIdentityEnvironmentRejectsAmbiguity(t *testing.T) {
	t.Parallel()
	valid := []string{
		"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
		"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
		"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
	}
	for name, values := range map[string][]string{
		"missing id": {
			"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
			"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
		},
		"duplicate id": {
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
		},
		"unknown key": {
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
			"TOKEN=secret",
		},
		"wrong snapshot": {
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_SNAPSHOT=registry.example/other@sha256:" + strings.Repeat("1", 64),
			"DAYTONA_SANDBOX_USER=" + terminalXSandboxUser,
		},
		"wrong user": {
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
			"DAYTONA_SANDBOX_USER=root",
		},
		"malformed": {
			"DAYTONA_SANDBOX_ID=" + testTerminalXSandboxUUID,
			"DAYTONA_SANDBOX_SNAPSHOT=" + testTerminalXSnapshotRef,
			"DAYTONA_SANDBOX_USER",
		},
	} {
		name, values := name, values
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if providerSandboxID, ok := terminalXProviderSandboxIDFromEnvironment(values, testTerminalXSnapshotRef); ok || providerSandboxID != "" {
				t.Fatal("ambiguous privileged environment was accepted")
			}
		})
	}
	providerSandboxID, ok := terminalXProviderSandboxIDFromEnvironment(valid, testTerminalXSnapshotRef)
	if !ok || providerSandboxID != testTerminalXSandboxUUID {
		t.Fatal("exact privileged environment was rejected")
	}
}

func TestTerminalXProvisionalReadinessNeverUsesPublicDaemonTCP(t *testing.T) {
	t.Parallel()
	client, inspected := terminalXContainerForTest(t)
	inspected.State = &container.State{Running: true}
	if err := client.requireTerminalXProvisionalReady(inspected); err != nil {
		t.Fatalf("valid provisional container rejected: %v", err)
	}
	if _, err := client.waitForDaemonRunning(context.Background(), "203.0.113.1", nil); !errors.Is(err, errTerminalXDaemonIsPrivate) {
		t.Fatalf("hardened daemon TCP poll was not closed: %v", err)
	}
	if _, err := client.GetDaemonVersion(context.Background(), testTerminalXSandboxUUID); !errors.Is(err, errTerminalXDaemonIsPrivate) {
		t.Fatalf("hardened daemon version route was not closed: %v", err)
	}

	inspected.State.Running = false
	if err := client.requireTerminalXProvisionalReady(inspected); err == nil {
		t.Fatal("stopped provisional container was accepted")
	}
	inspected.State.Running = true
	inspected.Config.Hostname = testTerminalXSandboxUUID
	if err := client.requireTerminalXProvisionalReady(inspected); err == nil {
		t.Fatal("drifted provisional container was accepted")
	}
}

func TestTerminalXGenericImageMutationPathsAreClosed(t *testing.T) {
	t.Parallel()
	client := &DockerClient{
		terminalXHardened:                         true,
		terminalXSandboxImageID:                   testTerminalXImageID,
		terminalXSandboxSnapshotRef:               testTerminalXSnapshotRef,
		terminalXSupervisorRelaySHA256:            testTerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapSHA256:        testTerminalXAssignmentBootstrapSHA256,
		terminalXNodeSHA256:                       testTerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerSHA256: testTerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeSHA256:             testTerminalXIsolationProbeSHA256,
	}
	ctx := context.Background()
	if _, err := client.PullImage(ctx, "example.invalid/image:latest", nil, nil); err == nil {
		t.Fatal("generic image pull was accepted")
	}
	if err := client.PullSnapshot(ctx, dto.PullSnapshotRequestDTO{}); err == nil {
		t.Fatal("snapshot pull was accepted")
	}
	if err := client.TagImage(ctx, testTerminalXImageID, "example.invalid/image:latest"); err == nil {
		t.Fatal("image tag was accepted")
	}
	if err := client.PushImage(ctx, testTerminalXImageID, nil); err == nil {
		t.Fatal("image push was accepted")
	}
	if err := client.RemoveImage(ctx, testTerminalXImageID, true); err == nil {
		t.Fatal("pinned image removal was accepted")
	}
}

func TestValidateTerminalXImageRequiresExactImmutableArtifact(t *testing.T) {
	t.Parallel()
	if err := validateTerminalXImage(terminalXImage(), testTerminalXImageID); err != nil {
		t.Fatalf("valid hardened image rejected: %v", err)
	}

	tests := map[string]func(*image.InspectResponse){
		"wrong id": func(v *image.InspectResponse) {
			v.ID = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		},
		"missing label": func(v *image.InspectResponse) { delete(v.Config.Labels, terminalXHardenedProfileLabel) },
		"declared volume": func(v *image.InspectResponse) {
			v.Config.Volumes = map[string]struct{}{`/data`: {}}
		},
		"wrong entrypoint": func(v *image.InspectResponse) { v.Config.Entrypoint = []string{"/bin/sh"} },
		"non-root init":    func(v *image.InspectResponse) { v.Config.User = terminalXSandboxUser },
		"healthcheck": func(v *image.InspectResponse) {
			v.Config.Healthcheck = &container.HealthConfig{Test: []string{"CMD", "id"}}
		},
		"default command": func(v *image.InspectResponse) { v.Config.Cmd = []string{"sh"} },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := terminalXImage()
			mutate(candidate)
			if err := validateTerminalXImage(candidate, testTerminalXImageID); err == nil {
				t.Fatal("untrusted image was accepted")
			}
		})
	}
}

func TestValidateTerminalXImageArtifactRequiresBothFixedExecutables(t *testing.T) {
	t.Parallel()
	client := &DockerClient{
		terminalXSandboxImageID:                   testTerminalXImageID,
		terminalXSupervisorRelaySHA256:            testTerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapSHA256:        testTerminalXAssignmentBootstrapSHA256,
		terminalXNodeSHA256:                       testTerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerSHA256: testTerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeSHA256:             testTerminalXIsolationProbeSHA256,
	}
	if err := client.validateTerminalXImageArtifact(terminalXImage()); err != nil {
		t.Fatalf("valid hardened image artifact rejected: %v", err)
	}
	for _, label := range []string{
		terminalXSupervisorRelayDigestLabel,
		terminalXAssignmentBootstrapDigestLabel,
		terminalXNodeDigestLabel,
		terminalXDeploymentBindingInstallerDigestLabel,
		terminalXIsolationProbeDigestLabel,
	} {
		candidate := terminalXImage()
		delete(candidate.Config.Labels, label)
		if err := client.validateTerminalXImageArtifact(candidate); err == nil {
			t.Fatalf("image without %s was accepted", label)
		}
	}
}

func TestTerminalXHostConfigHasNoPrivilegedOrUnboundedPath(t *testing.T) {
	t.Parallel()
	client := &DockerClient{terminalXHardened: true, filesystem: "xfs"}
	request := terminalXCreateRequest()
	host, err := client.terminalXHostConfig(request, nil, nil)
	if err != nil {
		t.Fatalf("host config failed: %v", err)
	}
	if host.Privileged || len(host.Binds) != 0 || len(host.Mounts) != 0 || len(host.VolumesFrom) != 0 {
		t.Fatal("host or shared mount access was enabled")
	}
	if host.PidsLimit == nil || *host.PidsLimit != terminalXSandboxPidsLimit {
		t.Fatal("process limit was not enforced")
	}
	if host.CPUQuota != request.CpuQuota*100000 || host.Memory <= 0 || host.MemorySwap != host.Memory {
		t.Fatal("cpu or memory limit was not enforced")
	}
	if host.StorageOpt["size"] != "20G" {
		t.Fatal("disk quota was not enforced")
	}
	if !slices.Equal([]string(host.CapDrop), []string{"ALL"}) ||
		!slices.Contains(host.SecurityOpt, "no-new-privileges:true") {
		t.Fatal("capability or privilege escalation hardening was not enforced")
	}
}

func TestTerminalXHostConfigFailsWithoutXFSOrWithMounts(t *testing.T) {
	t.Parallel()
	request := terminalXCreateRequest()
	client := &DockerClient{terminalXHardened: true, filesystem: "ext4"}
	if _, err := client.terminalXHostConfig(request, nil, nil); err == nil {
		t.Fatal("non-XFS storage was accepted")
	}
	client.filesystem = "xfs"
	if _, err := client.terminalXHostConfig(request, []string{"/host:/sandbox"}, nil); err == nil {
		t.Fatal("host bind was accepted")
	}
}

func TestRequireTerminalXContainerRejectsRuntimeBoundaryDrift(t *testing.T) {
	t.Parallel()

	client, valid := terminalXContainerForTest(t)
	if err := client.requireTerminalXContainer(valid); err != nil {
		t.Fatalf("valid container rejected: %v", err)
	}
	tests := map[string]func(*container.InspectResponse){
		"wrong image": func(v *container.InspectResponse) { v.Image = "sha256:" + string(make([]byte, 64)) },
		"provider identity hostname": func(v *container.InspectResponse) {
			v.Config.Hostname = testTerminalXSandboxUUID
		},
		"non uuid sandbox identity": func(v *container.InspectResponse) {
			v.Config.Env[0] = "DAYTONA_SANDBOX_ID=sandbox-1"
		},
		"uppercase sandbox identity": func(v *container.InspectResponse) {
			v.Config.Env[0] = "DAYTONA_SANDBOX_ID=123E4567-E89B-42D3-A456-426614174000"
		},
		"relay digest drift": func(v *container.InspectResponse) {
			delete(v.Config.Labels, terminalXSupervisorRelayDigestLabel)
		},
		"bootstrap digest drift": func(v *container.InspectResponse) {
			delete(v.Config.Labels, terminalXAssignmentBootstrapDigestLabel)
		},
		"node digest drift": func(v *container.InspectResponse) {
			delete(v.Config.Labels, terminalXNodeDigestLabel)
		},
		"host bind": func(v *container.InspectResponse) { v.HostConfig.Binds = []string{"/host:/sandbox"} },
		"device": func(v *container.InspectResponse) {
			v.HostConfig.Devices = []container.DeviceMapping{{PathOnHost: "/dev/kvm"}}
		},
		"extra capability": func(v *container.InspectResponse) {
			v.HostConfig.CapAdd = append(v.HostConfig.CapAdd, "SYS_ADMIN")
		},
		"unconfined seccomp": func(v *container.InspectResponse) {
			v.HostConfig.SecurityOpt = append(v.HostConfig.SecurityOpt, "seccomp=unconfined")
		},
		"host network":      func(v *container.InspectResponse) { v.HostConfig.NetworkMode = "host" },
		"alternate runtime": func(v *container.InspectResponse) { v.HostConfig.Runtime = "kata" },
		"cpu period drift":  func(v *container.InspectResponse) { v.HostConfig.CPUPeriod = 0 },
		"memory drift":      func(v *container.InspectResponse) { v.HostConfig.Memory++ },
		"disk drift":        func(v *container.InspectResponse) { v.HostConfig.StorageOpt["size"] = "999999G" },
		"restart policy": func(v *container.InspectResponse) {
			v.HostConfig.RestartPolicy = container.RestartPolicy{Name: "always"}
		},
		"shared ipc": func(v *container.InspectResponse) {
			v.HostConfig.IpcMode = container.IpcMode("container:other")
		},
		"shareable ipc": func(v *container.InspectResponse) {
			v.HostConfig.IpcMode = container.IpcMode("shareable")
		},
		"shared cgroup namespace": func(v *container.InspectResponse) {
			v.HostConfig.CgroupnsMode = container.CgroupnsMode("host")
		},
		"tmpfs mount": func(v *container.InspectResponse) {
			v.HostConfig.Tmpfs = map[string]string{"/run": "rw"}
		},
		"healthcheck": func(v *container.InspectResponse) {
			v.Config.Healthcheck = &container.HealthConfig{Test: []string{"CMD", "id"}}
		},
		"disabled init": func(v *container.InspectResponse) {
			value := false
			v.HostConfig.Init = &value
		},
		"host logging": func(v *container.InspectResponse) {
			v.HostConfig.LogConfig = container.LogConfig{Type: "json-file"}
		},
		"masked path drift": func(v *container.InspectResponse) {
			v.HostConfig.MaskedPaths = v.HostConfig.MaskedPaths[1:]
		},
		"environment injection": func(v *container.InspectResponse) {
			v.Config.Env = append(v.Config.Env, "TOKEN=secret")
		},
		"second network": func(v *container.InspectResponse) {
			v.NetworkSettings.Networks["bridge"] = &network.EndpointSettings{IPAddress: "172.17.0.2"}
		},
		"outside runner subnet": func(v *container.InspectResponse) {
			v.NetworkSettings.Networks[RUNNER_BRIDGE_NETWORK_NAME].IPAddress = "172.21.0.2"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			client, candidate := terminalXContainerForTest(t)
			mutate(candidate)
			if err := client.requireTerminalXContainer(candidate); err == nil {
				t.Fatal("drifted container was accepted")
			}
		})
	}
}

func TestHasTerminalXSeccompRejectsMissingOrUnconfined(t *testing.T) {
	t.Parallel()
	if !hasTerminalXSeccomp([]string{"name=seccomp,profile=builtin"}) {
		t.Fatal("docker builtin seccomp profile was rejected")
	}
	if hasTerminalXSeccomp(nil) || hasTerminalXSeccomp([]string{"name=seccomp,profile=unconfined"}) {
		t.Fatal("missing or unconfined seccomp was accepted")
	}
}

func TestValidateTerminalXRunnerRequirementsFailsClosed(t *testing.T) {
	t.Parallel()
	valid := func() terminalXRunnerRequirements {
		return terminalXRunnerRequirements{
			imageID:                          testTerminalXImageID,
			snapshotRef:                      testTerminalXSnapshotRef,
			useSnapshotEntrypoint:            true,
			networkEnforcementAvailable:      true,
			storageDriver:                    "overlay2",
			backingFilesystem:                "xfs",
			securityOptions:                  []string{"name=seccomp,profile=builtin"},
			defaultRuntime:                   "runc",
			cgroupVersion:                    "2",
			expectedDockerServerVersion:      "28.5.2",
			actualDockerServerVersion:        "28.5.2",
			expectedContainerdCommit:         "containerd-commit",
			actualContainerdCommit:           "containerd-commit",
			expectedRuncCommit:               "runc-commit",
			actualRuncCommit:                 "runc-commit",
			memoryLimitAvailable:             true,
			swapLimitAvailable:               true,
			cpuQuotaAvailable:                true,
			pidsLimitAvailable:               true,
			oomKillAvailable:                 true,
			supervisorRelaySHA256:            testTerminalXSupervisorRelaySHA256,
			assignmentBootstrapSHA256:        testTerminalXAssignmentBootstrapSHA256,
			nodeSHA256:                       testTerminalXNodeSHA256,
			deploymentBindingInstallerSHA256: testTerminalXDeploymentBindingInstallerSHA256,
			isolationProbeSHA256:             testTerminalXIsolationProbeSHA256,
		}
	}
	if err := validateTerminalXRunnerRequirements(valid()); err != nil {
		t.Fatalf("valid hardened runner rejected: %v", err)
	}
	tests := map[string]func(*terminalXRunnerRequirements){
		"missing image pin":            func(v *terminalXRunnerRequirements) { v.imageID = "" },
		"missing snapshot pin":         func(v *terminalXRunnerRequirements) { v.snapshotRef = "" },
		"limits disabled":              func(v *terminalXRunnerRequirements) { v.resourceLimitsDisabled = true },
		"entrypoint override":          func(v *terminalXRunnerRequirements) { v.useSnapshotEntrypoint = false },
		"inter-sandbox network":        func(v *terminalXRunnerRequirements) { v.interSandboxNetworkEnabled = true },
		"additional network":           func(v *terminalXRunnerRequirements) { v.containerNetwork = "bridge" },
		"runtime override":             func(v *terminalXRunnerRequirements) { v.containerRuntime = "kata" },
		"wrong default runtime":        func(v *terminalXRunnerRequirements) { v.defaultRuntime = "nvidia" },
		"legacy cgroup":                func(v *terminalXRunnerRequirements) { v.cgroupVersion = "1" },
		"gpu":                          func(v *terminalXRunnerRequirements) { v.gpuEnabled = true },
		"kvm":                          func(v *terminalXRunnerRequirements) { v.mountKvm = true },
		"daemon token injection":       func(v *terminalXRunnerRequirements) { v.initializeDaemonTelemetry = true },
		"missing network enforcer":     func(v *terminalXRunnerRequirements) { v.networkEnforcementAvailable = false },
		"wrong storage driver":         func(v *terminalXRunnerRequirements) { v.storageDriver = "btrfs" },
		"wrong backing filesystem":     func(v *terminalXRunnerRequirements) { v.backingFilesystem = "ext4" },
		"missing seccomp":              func(v *terminalXRunnerRequirements) { v.securityOptions = nil },
		"missing docker pin":           func(v *terminalXRunnerRequirements) { v.expectedDockerServerVersion = "" },
		"docker version drift":         func(v *terminalXRunnerRequirements) { v.actualDockerServerVersion = "28.5.3" },
		"containerd drift":             func(v *terminalXRunnerRequirements) { v.actualContainerdCommit = "different" },
		"runc drift":                   func(v *terminalXRunnerRequirements) { v.actualRuncCommit = "different" },
		"missing memory limits":        func(v *terminalXRunnerRequirements) { v.memoryLimitAvailable = false },
		"missing swap limits":          func(v *terminalXRunnerRequirements) { v.swapLimitAvailable = false },
		"missing cpu quotas":           func(v *terminalXRunnerRequirements) { v.cpuQuotaAvailable = false },
		"missing pid limits":           func(v *terminalXRunnerRequirements) { v.pidsLimitAvailable = false },
		"missing oom enforcement":      func(v *terminalXRunnerRequirements) { v.oomKillAvailable = false },
		"live restore":                 func(v *terminalXRunnerRequirements) { v.liveRestoreEnabled = true },
		"missing supervisor relay":     func(v *terminalXRunnerRequirements) { v.supervisorRelaySHA256 = "" },
		"missing assignment bootstrap": func(v *terminalXRunnerRequirements) { v.assignmentBootstrapSHA256 = "" },
		"missing node interpreter":     func(v *terminalXRunnerRequirements) { v.nodeSHA256 = "" },
		"missing binding installer":    func(v *terminalXRunnerRequirements) { v.deploymentBindingInstallerSHA256 = "" },
		"missing isolation probe":      func(v *terminalXRunnerRequirements) { v.isolationProbeSHA256 = "" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := valid()
			mutate(&candidate)
			if err := validateTerminalXRunnerRequirements(candidate); err == nil {
				t.Fatal("unsafe runner configuration was accepted")
			}
		})
	}
}

func TestValidateTerminalXRunnerNetworkRequiresPrivateIPv4Bridge(t *testing.T) {
	t.Parallel()
	valid := func() network.Inspect {
		return network.Inspect{
			Name:       RUNNER_BRIDGE_NETWORK_NAME,
			Scope:      "local",
			Driver:     "bridge",
			EnableIPv4: true,
			Internal:   true,
			Options: map[string]string{
				"com.docker.network.bridge.enable_icc": "false",
			},
			Labels: map[string]string{
				terminalXNetworkProfileLabel: terminalXHardenedProfileVersion,
			},
			IPAM: network.IPAM{
				Driver: "default",
				Config: []network.IPAMConfig{{Subnet: "172.20.0.0/16"}},
			},
		}
	}
	if err := validateTerminalXRunnerNetwork(valid()); err != nil {
		t.Fatalf("valid runner network rejected: %v", err)
	}
	tests := map[string]func(*network.Inspect){
		"external":        func(v *network.Inspect) { v.Internal = false },
		"ipv4 disabled":   func(v *network.Inspect) { v.EnableIPv4 = false },
		"ipv6 enabled":    func(v *network.Inspect) { v.EnableIPv6 = true },
		"icc enabled":     func(v *network.Inspect) { v.Options["com.docker.network.bridge.enable_icc"] = "true" },
		"missing profile": func(v *network.Inspect) { delete(v.Labels, terminalXNetworkProfileLabel) },
		"wrong subnet":    func(v *network.Inspect) { v.IPAM.Config[0].Subnet = "172.21.0.0/16" },
		"overlay":         func(v *network.Inspect) { v.Driver = "overlay" },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidate := valid()
			mutate(&candidate)
			if err := validateTerminalXRunnerNetwork(candidate); err == nil {
				t.Fatal("unsafe runner network was accepted")
			}
		})
	}
}
