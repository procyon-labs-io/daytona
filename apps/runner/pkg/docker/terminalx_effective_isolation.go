// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	terminalXEffectiveIsolationKind               = "terminalx.daytona-effective-isolation"
	terminalXEffectiveIsolationClaimsDigestDomain = "terminalx/daytona-effective-isolation-claims/v1\x00"
	terminalXEffectiveIsolationSignatureDomain    = "terminalx/daytona-effective-isolation-authority/v1\x00"
	terminalXProviderIdentityDigestDomain         = "terminalx/daytona-provider-identity/v1\x00"
	terminalXObservationProvisioningDigestDomain  = "terminalx/daytona-observation-key-provisioning-ref/v1\x00"
	terminalXIsolationProbeKind                   = "terminalx.daytona-isolation-probe"

	terminalXIsolationProbeMaximumArtifactBytes int64 = 16 * 1024 * 1024
	terminalXIsolationProbeMaximumOutputBytes   int64 = 64 * 1024
	terminalXIsolationProbeMaximumStderrBytes   int64 = 4 * 1024
	terminalXEffectiveIsolationMaximumBytes           = 256 * 1024
	terminalXIsolationProbeTimeout                    = 10 * time.Second
)

var terminalXCapabilityMask = regexp.MustCompile(`^[0-9a-f]{16}$`)

type terminalXIsolationProbeProcess struct {
	CapAmbient      string `json:"capAmbient"`
	CapBounding     string `json:"capBounding"`
	CapEffective    string `json:"capEffective"`
	CapInheritable  string `json:"capInheritable"`
	CapPermitted    string `json:"capPermitted"`
	EffectiveGID    int64  `json:"effectiveGid"`
	EffectiveUID    int64  `json:"effectiveUid"`
	FilesystemGID   int64  `json:"filesystemGid"`
	FilesystemUID   int64  `json:"filesystemUid"`
	NoNewPrivileges bool   `json:"noNewPrivileges"`
	PID             int64  `json:"pid"`
	RealGID         int64  `json:"realGid"`
	RealUID         int64  `json:"realUid"`
	SavedGID        int64  `json:"savedGid"`
	SavedUID        int64  `json:"savedUid"`
}

type terminalXIsolationProbeAgent struct {
	CapAmbient      string `json:"capAmbient"`
	CapBounding     string `json:"capBounding"`
	CapEffective    string `json:"capEffective"`
	CapInheritable  string `json:"capInheritable"`
	CapPermitted    string `json:"capPermitted"`
	EffectiveGID    int64  `json:"effectiveGid"`
	EffectiveUID    int64  `json:"effectiveUid"`
	FilesystemGID   int64  `json:"filesystemGid"`
	FilesystemUID   int64  `json:"filesystemUid"`
	NoNewPrivileges bool   `json:"noNewPrivileges"`
	ProcessCount    int64  `json:"processCount"`
	RealGID         int64  `json:"realGid"`
	RealUID         int64  `json:"realUid"`
	SavedGID        int64  `json:"savedGid"`
	SavedUID        int64  `json:"savedUid"`
}

type terminalXIsolationProbeDenials struct {
	AgentPrivateKeyReadDenied   bool `json:"agentPrivateKeyReadDenied"`
	AgentPrivateKeyWriteDenied  bool `json:"agentPrivateKeyWriteDenied"`
	AgentRootRuntimeWriteDenied bool `json:"agentRootRuntimeWriteDenied"`
	AgentRootStateWriteDenied   bool `json:"agentRootStateWriteDenied"`
	AgentSignalInitDenied       bool `json:"agentSignalInitDenied"`
	AgentSignalSupervisorDenied bool `json:"agentSignalSupervisorDenied"`
}

type terminalXIsolationProbeExecutable struct {
	GID     int64  `json:"gid"`
	Mode    int64  `json:"mode"`
	NLink   int64  `json:"nlink"`
	Path    string `json:"path"`
	Regular bool   `json:"regular"`
	UID     int64  `json:"uid"`
}

type terminalXIsolationProbePrivatePath struct {
	GID   int64  `json:"gid"`
	Mode  int64  `json:"mode"`
	NLink int64  `json:"nlink"`
	Path  string `json:"path"`
	Type  string `json:"type"`
	UID   int64  `json:"uid"`
}

type terminalXIsolationProbeReport struct {
	Agent            terminalXIsolationProbeAgent         `json:"agent"`
	Daemon           terminalXIsolationProbeProcess       `json:"daemon"`
	Denials          terminalXIsolationProbeDenials       `json:"denials"`
	Executables      []terminalXIsolationProbeExecutable  `json:"executables"`
	Init             terminalXIsolationProbeProcess       `json:"init"`
	Kind             string                               `json:"kind"`
	RootPrivatePaths []terminalXIsolationProbePrivatePath `json:"rootPrivatePaths"`
	Supervisor       terminalXIsolationProbeProcess       `json:"supervisor"`
	Version          int                                  `json:"version"`
}

type terminalXEffectiveIsolationResources struct {
	CPU       int64 `json:"cpu"`
	DiskGiB   int64 `json:"diskGiB"`
	MemoryGiB int64 `json:"memoryGiB"`
	Pids      int64 `json:"pids"`
}

type terminalXEffectiveIsolationSource struct {
	BaseAncestryVerified bool   `json:"baseAncestryVerified"`
	BaseCommit           string `json:"baseCommit"`
	HardenedCommit       string `json:"hardenedCommit"`
}

type terminalXEffectiveIsolationImage struct {
	AuthorizationHeaderForwardedToSandbox         bool   `json:"authorizationHeaderForwardedToSandbox"`
	DaytonaDaemonBundled                          bool   `json:"daytonaDaemonBundled"`
	Entrypoint                                    string `json:"entrypoint"`
	InitializeDaemonTelemetry                     bool   `json:"initializeDaemonTelemetry"`
	OtelEnvironmentInjected                       bool   `json:"otelEnvironmentInjected"`
	ProviderSandboxTokenInjected                  bool   `json:"providerSandboxTokenInjected"`
	RootSecretsExcludedFromCheckpoints            bool   `json:"rootSecretsExcludedFromCheckpoints"`
	SandboxImageID                                string `json:"sandboxImageId"`
	SandboxProfileLabel                           string `json:"sandboxProfileLabel"`
	SandboxSnapshotRef                            string `json:"sandboxSnapshotRef"`
	TerminalXHardened                             bool   `json:"terminalxHardened"`
	UseSnapshotEntrypoint                         bool   `json:"useSnapshotEntrypoint"`
	XDaytonaAuthorizationHeaderForwardedToSandbox bool   `json:"xDaytonaAuthorizationHeaderForwardedToSandbox"`
}

type terminalXEffectiveIsolationRunnerEnforcement struct {
	BackingFilesystem                  string `json:"backingFilesystem"`
	BackupsDisabled                    bool   `json:"backupsDisabled"`
	BlockAllEgressInstalledBeforeStart bool   `json:"blockAllEgressInstalledBeforeStart"`
	BuiltInSeccomp                     bool   `json:"builtInSeccomp"`
	ContainerdVersion                  string `json:"containerdVersion"`
	DockerDriver                       string `json:"dockerDriver"`
	DockerUserEgressDropBeforeStart    bool   `json:"dockerUserEgressDropBeforeStart"`
	DockerVersion                      string `json:"dockerVersion"`
	GenericBuildsDisabled              bool   `json:"genericBuildsDisabled"`
	InputEstablishedRepliesAllowed     bool   `json:"inputEstablishedRepliesAllowed"`
	InputHostNewDrop                   bool   `json:"inputHostNewDrop"`
	InterSandboxNetworking             bool   `json:"interSandboxNetworking"`
	ResizesDisabled                    bool   `json:"resizesDisabled"`
	ResourceLimitsEnabled              bool   `json:"resourceLimitsEnabled"`
	SnapshotsDisabled                  bool   `json:"snapshotsDisabled"`
	XFSProjectQuotaEnabled             bool   `json:"xfsProjectQuotaEnabled"`
}

type terminalXEffectiveIsolationRunnerNetwork struct {
	Driver                      string `json:"driver"`
	InterContainerCommunication bool   `json:"interContainerCommunication"`
	Internal                    bool   `json:"internal"`
	IPv4Only                    bool   `json:"ipv4Only"`
	Label                       string `json:"label"`
	Scope                       string `json:"scope"`
	Subnet                      string `json:"subnet"`
}

type terminalXEffectiveIsolationControls struct {
	AgentAmbientCapabilitiesEmpty     bool     `json:"agentAmbientCapabilitiesEmpty"`
	AgentEffectiveCapabilitiesEmpty   bool     `json:"agentEffectiveCapabilitiesEmpty"`
	AgentInheritableCapabilitiesEmpty bool     `json:"agentInheritableCapabilitiesEmpty"`
	AgentNoNewPrivileges              bool     `json:"agentNoNewPrivileges"`
	AgentPermittedCapabilitiesEmpty   bool     `json:"agentPermittedCapabilitiesEmpty"`
	CapDropAll                        bool     `json:"capDropAll"`
	CapabilitiesDropped               bool     `json:"capabilitiesDropped"`
	HostMounts                        bool     `json:"hostMounts"`
	HostNetwork                       bool     `json:"hostNetwork"`
	ImageDeclaredVolumes              int      `json:"imageDeclaredVolumes"`
	LinkedSandbox                     bool     `json:"linkedSandbox"`
	NoNewPrivileges                   bool     `json:"noNewPrivileges"`
	PidsLimit                         int64    `json:"pidsLimit"`
	PrivateWritableOverlay            bool     `json:"privateWritableOverlay"`
	Privileged                        bool     `json:"privileged"`
	PublicAccess                      bool     `json:"publicAccess"`
	ReadOnlyRootFilesystem            bool     `json:"readOnlyRootFilesystem"`
	RootIdentity                      bool     `json:"rootIdentity"`
	RootInitCapAdd                    []string `json:"rootInitCapAdd"`
	SeccompProfileDigest              string   `json:"seccompProfileDigest"`
	ZeroExternalMounts                bool     `json:"zeroExternalMounts"`
}

type terminalXEffectiveIsolationProcessBoundary struct {
	AgentCanAccessCredentialChannel   bool  `json:"agentCanAccessCredentialChannel"`
	AgentCanReadObservationKey        bool  `json:"agentCanReadObservationKey"`
	AgentCanReadSupervisorState       bool  `json:"agentCanReadSupervisorState"`
	AgentCanSignalSupervisor          bool  `json:"agentCanSignalSupervisor"`
	AgentCanWriteEffectExecutor       bool  `json:"agentCanWriteEffectExecutor"`
	AgentCanWriteSupervisorExecutable bool  `json:"agentCanWriteSupervisorExecutable"`
	AgentUID                          int64 `json:"agentUid"`
	DaytonaDaemonUID                  int64 `json:"daytonaDaemonUid"`
	ObservationKeyOwnerUID            int64 `json:"observationKeyOwnerUid"`
	RootOwnedLocalCredentialChannel   bool  `json:"rootOwnedLocalCredentialChannel"`
	StateOwnerUID                     int64 `json:"stateOwnerUid"`
	SupervisorUID                     int64 `json:"supervisorUid"`
}

type terminalXEffectiveIsolationClaims struct {
	ArtifactDigest                      string                                       `json:"artifactDigest"`
	Controls                            terminalXEffectiveIsolationControls          `json:"controls"`
	ExpiresAtMS                         int64                                        `json:"expiresAtMs"`
	HardenedImage                       terminalXEffectiveIsolationImage             `json:"hardenedImage"`
	IsolationPolicyDigest               string                                       `json:"isolationPolicyDigest"`
	NetworkPolicyDigest                 string                                       `json:"networkPolicyDigest"`
	ObservationIssuerKeyID              string                                       `json:"observationIssuerKeyId"`
	ObservationKeyProvisioningRefDigest string                                       `json:"observationKeyProvisioningRefDigest"`
	ObservationPublicKeyDigest          string                                       `json:"observationPublicKeyDigest"`
	ObservedAtMS                        int64                                        `json:"observedAtMs"`
	PlanDigest                          string                                       `json:"planDigest"`
	ProcessBoundary                     terminalXEffectiveIsolationProcessBoundary   `json:"processBoundary"`
	ProviderIdentityCommitment          string                                       `json:"providerIdentityCommitment"`
	ProviderRevision                    uint64                                       `json:"providerRevision"`
	Resources                           terminalXEffectiveIsolationResources         `json:"resources"`
	RunnerBinaryDigest                  string                                       `json:"runnerBinaryDigest"`
	RunnerEnforcement                   terminalXEffectiveIsolationRunnerEnforcement `json:"runnerEnforcement"`
	RunnerNetwork                       terminalXEffectiveIsolationRunnerNetwork     `json:"runnerNetwork"`
	SandboxUser                         string                                       `json:"sandboxUser"`
	Source                              terminalXEffectiveIsolationSource            `json:"source"`
	SupervisorArtifactDigest            string                                       `json:"supervisorArtifactDigest"`
	Version                             int                                          `json:"version"`
}

type terminalXEffectiveIsolationAuthority struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Signature    string `json:"signature"`
}

type terminalXEffectiveIsolationStatement struct {
	Audience     string `json:"audience"`
	Capability   string `json:"capability"`
	ClaimsDigest string `json:"claimsDigest"`
	ExpiresAtMS  int64  `json:"expiresAtMs"`
	IssuedAtMS   int64  `json:"issuedAtMs"`
	Issuer       string `json:"issuer"`
	IssuerKeyID  string `json:"issuerKeyId"`
	Version      int    `json:"version"`
}

type terminalXEffectiveIsolationAttestation struct {
	Authority terminalXEffectiveIsolationAuthority `json:"authority"`
	Claims    terminalXEffectiveIsolationClaims    `json:"claims"`
	Kind      string                               `json:"kind"`
	Version   int                                  `json:"version"`
}

type terminalXSupervisorRelayPreflight func(
	context.Context,
	[]byte,
	*container.InspectResponse,
) ([]byte, error)

func (d *DockerClient) prepareTerminalXSupervisorRelay(
	ctx context.Context,
	externalInput []byte,
	inspected *container.InspectResponse,
) ([]byte, error) {
	if d.terminalXSupervisorRelayPreflight != nil {
		return d.terminalXSupervisorRelayPreflight(ctx, externalInput, inspected)
	}
	configuration, err := d.readTerminalXInstalledAssignmentConfiguration(ctx, inspected)
	if err != nil {
		return nil, fmt.Errorf("terminalx installed assignment is unavailable: %w", err)
	}
	defer configuration.Close()
	report, err := d.runTerminalXIsolationProbe(ctx, inspected.ID)
	if err != nil {
		return nil, err
	}
	evidence, err := d.createTerminalXEffectiveIsolationAttestation(ctx, inspected, configuration, report)
	if err != nil {
		return nil, err
	}
	defer zeroTerminalXBytes(evidence)
	if len(evidence) < 2 || len(evidence) > terminalXEffectiveIsolationMaximumBytes ||
		len(externalInput) < 6 || len(externalInput) > terminalXSupervisorRelayMaximumInputBytes {
		return nil, fmt.Errorf("terminalx supervisor relay evidence is invalid")
	}
	result := make([]byte, 4+len(evidence)+len(externalInput))
	binary.BigEndian.PutUint32(result[:4], uint32(len(evidence)))
	copy(result[4:], evidence)
	copy(result[4+len(evidence):], externalInput)
	return result, nil
}

func (d *DockerClient) createTerminalXEffectiveIsolationAttestation(
	ctx context.Context,
	inspected *container.InspectResponse,
	configuration *terminalXAssignmentEvidenceConfiguration,
	report *terminalXIsolationProbeReport,
) ([]byte, error) {
	if configuration == nil || report == nil || d.terminalXIsolationAttestorSigner == nil ||
		!d.terminalXHardened || !d.useSnapshotEntrypoint ||
		d.resourceLimitsDisabled || d.filesystem != "xfs" || d.interSandboxNetworkEnabled ||
		d.initializeDaemonTelemetry || d.terminalXEvidenceTTL <= 0 ||
		d.terminalXEvidenceTTL > terminalXMaximumEvidenceTTL ||
		d.terminalXDaytonaDaemonUID != terminalXSandboxUserUID ||
		d.terminalXAgentUID != terminalXSandboxUserUID ||
		!terminalXGitCommit.MatchString(d.terminalXRunnerSourceCommit) ||
		d.terminalXRunnerSourceCommit == terminalXDaytonaBaseCommit ||
		!terminalXSha256Raw.MatchString(d.terminalXRunnerBinaryDigest) ||
		!terminalXSha256Raw.MatchString(d.terminalXSeccompProfileSHA256) ||
		!terminalXSafeTextReference.MatchString(d.terminalXDockerVersion) ||
		!terminalXSafeTextReference.MatchString(d.terminalXContainerdVersion) ||
		inspected == nil || inspected.State == nil || !inspected.State.Running {
		return nil, fmt.Errorf("terminalx effective isolation evidence is unavailable")
	}
	if err := d.requireTerminalXContainer(inspected); err != nil {
		return nil, err
	}
	actualNetwork, err := d.apiClient.NetworkInspect(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.InspectOptions{})
	if err != nil || validateTerminalXRunnerNetwork(actualNetwork) != nil {
		return nil, fmt.Errorf("terminalx runner network evidence is unavailable")
	}
	if err := validateTerminalXIsolationProbeReport(report); err != nil {
		return nil, err
	}
	providerSandboxID, environmentMatches := terminalXProviderSandboxIDFromEnvironment(
		inspected.Config.Env,
		d.terminalXSandboxSnapshotRef,
	)
	if inspected.Config.Hostname != terminalXHardenedHostname || !environmentMatches ||
		providerSandboxID != configuration.Assignment.ProviderSandboxID ||
		inspected.Image != configuration.Isolation.ExpectedSandboxImageID ||
		configuration.Isolation.ExpectedRunnerBinaryDigest != d.terminalXRunnerBinaryDigest ||
		configuration.Isolation.HardenedDaytonaSourceCommit != d.terminalXRunnerSourceCommit ||
		configuration.PlanDigest == "" || configuration.Assignment.ArtifactDigest != d.terminalXSandboxArtifactDigest {
		return nil, fmt.Errorf("terminalx effective isolation assignment does not match")
	}
	clock := d.terminalXClock
	if clock == nil {
		clock = time.Now
	}
	observedAtMS := clock().UnixMilli()
	ttlMS := d.terminalXEvidenceTTL.Milliseconds()
	maximumTimestamp := int64(terminalXJavaScriptMaximumSafeInteger)
	if observedAtMS < 0 || observedAtMS > maximumTimestamp || ttlMS < 1 ||
		ttlMS > terminalXMaximumEvidenceTTL.Milliseconds() || observedAtMS > maximumTimestamp-ttlMS {
		return nil, fmt.Errorf("terminalx effective isolation lifetime is invalid")
	}
	expiresAtMS := observedAtMS + ttlMS
	providerIdentityCommitment := terminalXDomainDigest(
		terminalXProviderIdentityDigestDomain,
		[]byte(configuration.Assignment.ProviderSandboxID),
	)
	observationPublicKeyDigest := terminalXRawDigest([]byte(configuration.Plan.Observation.PublicKeySPKIPEM))
	observationProvisioningDigest := terminalXDomainDigest(
		terminalXObservationProvisioningDigestDomain,
		[]byte(configuration.Plan.Observation.KeyProvisioningRef),
	)
	resources := configuration.Plan.Isolation.Resources
	claims := terminalXEffectiveIsolationClaims{
		ArtifactDigest:                      configuration.Assignment.ArtifactDigest,
		ExpiresAtMS:                         expiresAtMS,
		IsolationPolicyDigest:               configuration.Plan.Isolation.IsolationPolicyDigest,
		NetworkPolicyDigest:                 configuration.Plan.Isolation.Network.PolicyDigest,
		ObservationIssuerKeyID:              configuration.Plan.Observation.IssuerKeyID,
		ObservationKeyProvisioningRefDigest: observationProvisioningDigest,
		ObservationPublicKeyDigest:          observationPublicKeyDigest,
		ObservedAtMS:                        observedAtMS,
		PlanDigest:                          configuration.PlanDigest,
		ProviderIdentityCommitment:          providerIdentityCommitment,
		ProviderRevision:                    configuration.Assignment.ExpectedRevision,
		Resources: terminalXEffectiveIsolationResources{
			CPU: resources.CPU, DiskGiB: resources.DiskGiB,
			MemoryGiB: resources.MemoryGiB, Pids: resources.Pids,
		},
		SandboxUser:              terminalXSandboxUser,
		RunnerBinaryDigest:       d.terminalXRunnerBinaryDigest,
		SupervisorArtifactDigest: configuration.Assignment.SupervisorArtifactDigest,
		Version:                  1,
		Source: terminalXEffectiveIsolationSource{
			BaseAncestryVerified: true,
			BaseCommit:           terminalXDaytonaBaseCommit,
			HardenedCommit:       d.terminalXRunnerSourceCommit,
		},
		HardenedImage: terminalXEffectiveIsolationImage{
			AuthorizationHeaderForwardedToSandbox:         false,
			DaytonaDaemonBundled:                          true,
			Entrypoint:                                    terminalXHardenedEntrypoint,
			InitializeDaemonTelemetry:                     false,
			OtelEnvironmentInjected:                       false,
			ProviderSandboxTokenInjected:                  false,
			RootSecretsExcludedFromCheckpoints:            true,
			SandboxImageID:                                d.terminalXSandboxImageID,
			SandboxProfileLabel:                           terminalXHardenedProfileLabel + "=" + terminalXHardenedProfileVersion,
			SandboxSnapshotRef:                            d.terminalXSandboxSnapshotRef,
			TerminalXHardened:                             true,
			UseSnapshotEntrypoint:                         true,
			XDaytonaAuthorizationHeaderForwardedToSandbox: false,
		},
		RunnerEnforcement: terminalXEffectiveIsolationRunnerEnforcement{
			BackingFilesystem:                  "xfs",
			BackupsDisabled:                    true,
			BlockAllEgressInstalledBeforeStart: true,
			BuiltInSeccomp:                     true,
			ContainerdVersion:                  d.terminalXContainerdVersion,
			DockerDriver:                       "overlay2",
			DockerUserEgressDropBeforeStart:    true,
			DockerVersion:                      d.terminalXDockerVersion,
			GenericBuildsDisabled:              true,
			InputEstablishedRepliesAllowed:     true,
			InputHostNewDrop:                   true,
			InterSandboxNetworking:             false,
			ResizesDisabled:                    true,
			ResourceLimitsEnabled:              true,
			SnapshotsDisabled:                  true,
			XFSProjectQuotaEnabled:             true,
		},
		RunnerNetwork: terminalXEffectiveIsolationRunnerNetwork{
			Driver:                      actualNetwork.Driver,
			InterContainerCommunication: false,
			Internal:                    actualNetwork.Internal,
			IPv4Only:                    actualNetwork.EnableIPv4 && !actualNetwork.EnableIPv6,
			Label:                       terminalXNetworkProfileLabel + "=" + actualNetwork.Labels[terminalXNetworkProfileLabel],
			Scope:                       actualNetwork.Scope,
			Subnet:                      actualNetwork.IPAM.Config[0].Subnet,
		},
		Controls: terminalXEffectiveIsolationControls{
			AgentAmbientCapabilitiesEmpty:     true,
			AgentEffectiveCapabilitiesEmpty:   true,
			AgentInheritableCapabilitiesEmpty: true,
			AgentNoNewPrivileges:              true,
			AgentPermittedCapabilitiesEmpty:   true,
			CapDropAll:                        true,
			CapabilitiesDropped:               true,
			HostMounts:                        false,
			HostNetwork:                       false,
			ImageDeclaredVolumes:              0,
			LinkedSandbox:                     false,
			NoNewPrivileges:                   true,
			PidsLimit:                         resources.Pids,
			PrivateWritableOverlay:            true,
			Privileged:                        false,
			PublicAccess:                      false,
			ReadOnlyRootFilesystem:            false,
			RootIdentity:                      false,
			RootInitCapAdd:                    []string{"CHOWN", "KILL", "SETGID", "SETUID"},
			SeccompProfileDigest:              d.terminalXSeccompProfileSHA256,
			ZeroExternalMounts:                true,
		},
		ProcessBoundary: terminalXEffectiveIsolationProcessBoundary{
			AgentCanAccessCredentialChannel:   false,
			AgentCanReadObservationKey:        false,
			AgentCanReadSupervisorState:       false,
			AgentCanSignalSupervisor:          false,
			AgentCanWriteEffectExecutor:       false,
			AgentCanWriteSupervisorExecutable: false,
			AgentUID:                          report.Agent.EffectiveUID,
			DaytonaDaemonUID:                  report.Daemon.EffectiveUID,
			ObservationKeyOwnerUID:            0,
			RootOwnedLocalCredentialChannel:   true,
			StateOwnerUID:                     0,
			SupervisorUID:                     report.Supervisor.EffectiveUID,
		},
	}
	claimsBytes, err := marshalTerminalXCanonicalJSON(claims)
	if err != nil {
		return nil, err
	}
	claimsDigest := terminalXDomainDigest(terminalXEffectiveIsolationClaimsDigestDomain, claimsBytes)
	statement := terminalXEffectiveIsolationStatement{
		Audience:     "terminalx-control-plane",
		Capability:   "runtime.isolation.attest",
		ClaimsDigest: claimsDigest,
		ExpiresAtMS:  expiresAtMS,
		IssuedAtMS:   observedAtMS,
		Issuer:       "runtime-isolation-enforcer",
		IssuerKeyID:  d.terminalXIsolationAttestorSigner.keyID,
		Version:      1,
	}
	signature, err := d.terminalXIsolationAttestorSigner.sign(
		terminalXEffectiveIsolationSignatureDomain,
		statement,
	)
	if err != nil {
		return nil, err
	}
	attestation := terminalXEffectiveIsolationAttestation{
		Authority: terminalXEffectiveIsolationAuthority{
			Audience: statement.Audience, Capability: statement.Capability,
			ClaimsDigest: statement.ClaimsDigest, ExpiresAtMS: statement.ExpiresAtMS,
			IssuedAtMS: statement.IssuedAtMS, Issuer: statement.Issuer,
			IssuerKeyID: statement.IssuerKeyID, Signature: signature,
		},
		Claims: claims, Kind: terminalXEffectiveIsolationKind, Version: 1,
	}
	evidence, err := marshalTerminalXCanonicalJSON(attestation)
	if err != nil || len(evidence) < 2 || len(evidence) > terminalXEffectiveIsolationMaximumBytes {
		zeroTerminalXBytes(evidence)
		return nil, fmt.Errorf("terminalx effective isolation evidence is invalid")
	}
	return evidence, nil
}

func (d *DockerClient) runTerminalXIsolationProbe(
	ctx context.Context,
	containerID string,
) (report *terminalXIsolationProbeReport, returnErr error) {
	probeCtx, cancel := context.WithTimeout(ctx, terminalXIsolationProbeTimeout)
	defer cancel()
	if err := d.verifyTerminalXRootExecutionBoundary(
		probeCtx,
		containerID,
		terminalXIsolationProbePath,
		terminalXIsolationProbeMaximumArtifactBytes,
		d.terminalXIsolationProbeSHA256,
	); err != nil {
		return nil, fmt.Errorf("terminalx isolation probe artifact is invalid: %w", err)
	}
	execResponse, err := d.apiClient.ContainerExecCreate(probeCtx, containerID, terminalXIsolationProbeExecOptions())
	if err != nil {
		return nil, fmt.Errorf("terminalx isolation probe could not be created: %w", err)
	}
	attached, err := d.apiClient.ContainerExecAttach(probeCtx, execResponse.ID, container.ExecStartOptions{
		Detach: false,
		Tty:    false,
	})
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("terminalx isolation probe could not attach: %w", err),
			d.ensureTerminalXExecTerminated(containerID, execResponse.ID),
		)
	}
	var closeOnce sync.Once
	closeAttached := func() { closeOnce.Do(func() { attached.Close() }) }
	stopCancellationClose := context.AfterFunc(probeCtx, closeAttached)
	execTerminated := false
	defer func() {
		stopCancellationClose()
		closeAttached()
		if !execTerminated {
			returnErr = errors.Join(returnErr, d.ensureTerminalXExecTerminated(containerID, execResponse.ID))
		}
	}()
	stdout := &terminalXBoundedBuffer{maximumBytes: terminalXIsolationProbeMaximumOutputBytes}
	stderr := &terminalXBoundedBuffer{maximumBytes: terminalXIsolationProbeMaximumStderrBytes}
	defer stdout.Zero()
	defer stderr.Zero()
	_, outputErr := stdcopy.StdCopy(stdout, stderr, attached.Reader)
	if outputErr != nil || probeCtx.Err() != nil {
		closeAttached()
	}
	if probeCtx.Err() != nil {
		return nil, fmt.Errorf("terminalx isolation probe timed out")
	}
	inspect, err := d.apiClient.ContainerExecInspect(probeCtx, execResponse.ID)
	if err != nil || inspect.Running {
		return nil, fmt.Errorf("terminalx isolation probe exit status is unavailable")
	}
	execTerminated = true
	if inspect.ExitCode != 0 || outputErr != nil || stderr.Len() != 0 {
		return nil, fmt.Errorf("terminalx isolation probe failed closed")
	}
	return parseTerminalXIsolationProbeReport(stdout.Bytes())
}

func terminalXIsolationProbeExecOptions() container.ExecOptions {
	return container.ExecOptions{
		User:         "0:0",
		Privileged:   false,
		Tty:          false,
		AttachStdin:  false,
		AttachStderr: true,
		AttachStdout: true,
		WorkingDir:   "/",
		Cmd:          []string{terminalXIsolationProbePath},
	}
}

func parseTerminalXIsolationProbeReport(value []byte) (*terminalXIsolationProbeReport, error) {
	_, generic, err := canonicalizeTerminalXJSON(value, int(terminalXIsolationProbeMaximumOutputBytes))
	if err != nil {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	top, err := terminalXExactObject(generic,
		"agent", "daemon", "denials", "executables", "init", "kind", "rootPrivatePaths", "supervisor", "version")
	if err != nil {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	if _, err = terminalXExactObject(top["agent"],
		"capAmbient", "capBounding", "capEffective", "capInheritable", "capPermitted", "effectiveGid",
		"effectiveUid", "filesystemGid", "filesystemUid", "noNewPrivileges", "processCount", "realGid",
		"realUid", "savedGid", "savedUid"); err != nil {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	for _, name := range []string{"daemon", "init", "supervisor"} {
		if _, err = terminalXExactObject(top[name],
			"capAmbient", "capBounding", "capEffective", "capInheritable", "capPermitted", "effectiveGid",
			"effectiveUid", "filesystemGid", "filesystemUid", "noNewPrivileges", "pid", "realGid",
			"realUid", "savedGid", "savedUid"); err != nil {
			return nil, fmt.Errorf("terminalx isolation probe output is invalid")
		}
	}
	if _, err = terminalXExactObject(top["denials"],
		"agentPrivateKeyReadDenied", "agentPrivateKeyWriteDenied", "agentRootRuntimeWriteDenied",
		"agentRootStateWriteDenied", "agentSignalInitDenied", "agentSignalSupervisorDenied"); err != nil {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	executables, ok := top["executables"].([]any)
	if !ok {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	for _, executable := range executables {
		if _, err = terminalXExactObject(executable, "gid", "mode", "nlink", "path", "regular", "uid"); err != nil {
			return nil, fmt.Errorf("terminalx isolation probe output is invalid")
		}
	}
	privatePaths, ok := top["rootPrivatePaths"].([]any)
	if !ok {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	for _, privatePath := range privatePaths {
		if _, err = terminalXExactObject(privatePath, "gid", "mode", "nlink", "path", "type", "uid"); err != nil {
			return nil, fmt.Errorf("terminalx isolation probe output is invalid")
		}
	}
	var report terminalXIsolationProbeReport
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return nil, fmt.Errorf("terminalx isolation probe output is invalid")
	}
	if err := validateTerminalXIsolationProbeReport(&report); err != nil {
		return nil, err
	}
	return &report, nil
}

func validateTerminalXIsolationProbeReport(report *terminalXIsolationProbeReport) error {
	if report == nil || report.Version != 1 || report.Kind != terminalXIsolationProbeKind ||
		!validTerminalXProbeAgent(report.Agent) ||
		!validTerminalXProbeProcess(report.Daemon, int64(terminalXSandboxUserUID), false) ||
		!validTerminalXProbeProcess(report.Init, 0, true) || report.Init.PID != 1 ||
		!validTerminalXProbeProcess(report.Supervisor, 0, true) || report.Supervisor.PID == report.Init.PID ||
		report.Daemon.PID == report.Init.PID || report.Daemon.PID == report.Supervisor.PID ||
		!report.Denials.AgentPrivateKeyReadDenied || !report.Denials.AgentPrivateKeyWriteDenied ||
		!report.Denials.AgentRootRuntimeWriteDenied || !report.Denials.AgentRootStateWriteDenied ||
		!report.Denials.AgentSignalInitDenied || !report.Denials.AgentSignalSupervisorDenied {
		return fmt.Errorf("terminalx isolation probe report does not prove the process boundary")
	}
	expectedExecutables := []struct {
		path string
		mode int64
	}{
		{"/usr/local/bin/daytona", 0o555},
		{"/usr/local/bin/node", 0o555},
		{"/usr/local/bin/terminalx-sandbox-init", 0o555},
		{"/usr/local/libexec/terminalx/terminalx-assignment-bootstrap", 0o555},
		{"/usr/local/libexec/terminalx/terminalx-daytona-supervisor", 0o555},
		{"/usr/local/libexec/terminalx/terminalx-deployment-binding-install", 0o555},
		{"/usr/local/libexec/terminalx/terminalx-effect-enforcer", 0o500},
		{"/usr/local/libexec/terminalx/terminalx-isolation-probe", 0o555},
		{"/usr/local/libexec/terminalx/terminalx-peercred", 0o500},
		{"/usr/local/libexec/terminalx/terminalx-supervisor-relay", 0o555},
	}
	if len(report.Executables) != len(expectedExecutables) {
		return fmt.Errorf("terminalx isolation probe executable inventory is invalid")
	}
	for index, expected := range expectedExecutables {
		actual := report.Executables[index]
		if actual.Path != expected.path || actual.Mode != expected.mode || actual.UID != 0 || actual.GID != 0 ||
			actual.NLink != 1 || !actual.Regular {
			return fmt.Errorf("terminalx isolation probe executable inventory is invalid")
		}
	}
	expectedPrivatePaths := []struct {
		path     string
		typeName string
		mode     int64
	}{
		{"/etc/terminalx", "directory", 0o500},
		{"/run/terminalx-private", "directory", 0o700},
		{"/run/terminalx-private/daytona-daemon.sock", "socket", 0o600},
		{"/run/terminalx-root", "directory", 0o700},
		{"/run/terminalx-root/assignment", "directory", 0o700},
		{"/run/terminalx-root/assignment/effect-enforcer-key.pk8", "file", 0o600},
		{"/run/terminalx-root/assignment/observation-key.pk8", "file", 0o600},
		{"/run/terminalx-root/assignment/state-signing.pk8", "file", 0o600},
		{"/run/terminalx-root/deployment-binding.json", "file", 0o600},
		{"/var/lib/terminalx-supervisor", "directory", 0o700},
	}
	if len(report.RootPrivatePaths) != len(expectedPrivatePaths) {
		return fmt.Errorf("terminalx isolation probe private-path inventory is invalid")
	}
	for index, expected := range expectedPrivatePaths {
		actual := report.RootPrivatePaths[index]
		validLinks := actual.NLink == 1
		if expected.typeName == "directory" {
			validLinks = actual.NLink >= 2 && actual.NLink <= int64(terminalXJavaScriptMaximumSafeInteger)
		}
		if actual.Path != expected.path || actual.Type != expected.typeName || actual.Mode != expected.mode ||
			actual.UID != 0 || actual.GID != 0 || !validLinks {
			return fmt.Errorf("terminalx isolation probe private-path inventory is invalid")
		}
	}
	return nil
}

const terminalXSandboxUserUID = 10001

func validTerminalXProbeAgent(agent terminalXIsolationProbeAgent) bool {
	return validTerminalXCapabilityMasks(agent.CapAmbient, agent.CapBounding, agent.CapEffective, agent.CapInheritable, agent.CapPermitted) &&
		agent.CapAmbient == "0000000000000000" && agent.CapBounding == "00000000000000e1" &&
		agent.CapEffective == "0000000000000000" && agent.CapInheritable == "0000000000000000" &&
		agent.CapPermitted == "0000000000000000" && agent.NoNewPrivileges &&
		agent.ProcessCount >= 1 && agent.ProcessCount <= 512 && terminalXProbeIDsMatch(
		agent.RealUID, agent.EffectiveUID, agent.SavedUID, agent.FilesystemUID,
		agent.RealGID, agent.EffectiveGID, agent.SavedGID, agent.FilesystemGID,
		terminalXSandboxUserUID,
	)
}

func validTerminalXProbeProcess(process terminalXIsolationProbeProcess, expectedID int64, root bool) bool {
	expectedActive := "0000000000000000"
	if root {
		expectedActive = "00000000000000e1"
	}
	return process.PID >= 1 && process.PID <= int64(terminalXJavaScriptMaximumSafeInteger) &&
		validTerminalXCapabilityMasks(process.CapAmbient, process.CapBounding, process.CapEffective, process.CapInheritable, process.CapPermitted) &&
		process.CapAmbient == "0000000000000000" && process.CapBounding == "00000000000000e1" &&
		process.CapEffective == expectedActive && process.CapInheritable == "0000000000000000" &&
		process.CapPermitted == expectedActive && process.NoNewPrivileges &&
		terminalXProbeIDsMatch(
			process.RealUID, process.EffectiveUID, process.SavedUID, process.FilesystemUID,
			process.RealGID, process.EffectiveGID, process.SavedGID, process.FilesystemGID,
			expectedID,
		)
}

func validTerminalXCapabilityMasks(values ...string) bool {
	for _, value := range values {
		if !terminalXCapabilityMask.MatchString(value) {
			return false
		}
	}
	return true
}

func terminalXProbeIDsMatch(
	realUID int64,
	effectiveUID int64,
	savedUID int64,
	filesystemUID int64,
	realGID int64,
	effectiveGID int64,
	savedGID int64,
	filesystemGID int64,
	expected int64,
) bool {
	return realUID == expected && effectiveUID == expected && savedUID == expected && filesystemUID == expected &&
		realGID == expected && effectiveGID == expected && savedGID == expected && filesystemGID == expected
}

func terminalXDomainDigest(domain string, value []byte) string {
	digest := sha256.New()
	_, _ = io.WriteString(digest, domain)
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}

func terminalXRawDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
