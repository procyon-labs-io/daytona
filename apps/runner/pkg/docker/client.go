// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/daytonaio/common-go/pkg/utils"
	"github.com/daytonaio/runner/pkg/cache"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
)

type DockerClientConfig struct {
	ApiClient                                  client.APIClient
	BackupInfoCache                            *cache.BackupInfoCache
	Logger                                     *slog.Logger
	AWSRegion                                  string
	AWSEndpointUrl                             string
	AWSAccessKeyId                             string
	AWSSecretAccessKey                         string
	DaemonPath                                 string
	ComputerUsePluginPath                      string
	NetRulesManager                            *netrules.NetRulesManager
	ResourceLimitsDisabled                     bool
	DaemonStartTimeoutSec                      int
	SandboxStartTimeoutSec                     int
	AndroidBootTimeoutSec                      int
	UseSnapshotEntrypoint                      bool
	VolumeCleanupInterval                      time.Duration
	VolumeCleanupDryRun                        bool
	VolumeCleanupExclusionPeriod               time.Duration
	BackupTimeoutMin                           int
	SnapshotPullTimeout                        time.Duration
	BuildTimeoutMin                            int
	BuildCPUCores                              int64
	BuildMemoryGB                              int64
	InitializeDaemonTelemetry                  bool
	InterSandboxNetworkEnabled                 bool
	GpuEnabled                                 bool
	MountKvmToAndroidSandbox                   bool
	ContainerNetwork                           string
	ContainerRuntime                           string
	TerminalXHardened                          bool
	TerminalXSandboxImageID                    string
	TerminalXSandboxSnapshotRef                string
	TerminalXDockerServerVersion               string
	TerminalXContainerdCommit                  string
	TerminalXRuncCommit                        string
	TerminalXSupervisorRelaySHA256             string
	TerminalXAssignmentBootstrapSHA256         string
	TerminalXNodeSHA256                        string
	TerminalXDeploymentBindingInstallerSHA256  string
	TerminalXIsolationProbeSHA256              string
	TerminalXSandboxArtifactDigest             string
	TerminalXRunnerSourceCommit                string
	TerminalXRunnerBinaryDigest                string
	TerminalXSeccompProfileSHA256              string
	TerminalXBootstrapAuthorityKeyID           string
	TerminalXBootstrapAuthorityPublicKeyFile   string
	TerminalXBootstrapAuthorityPublicKeySHA256 string
	TerminalXDeploymentBindingKeyID            string
	TerminalXDeploymentBindingPrivateKeyFile   string
	TerminalXDeploymentBindingPublicKeySHA256  string
	TerminalXIsolationAttestorKeyID            string
	TerminalXIsolationAttestorPrivateKeyFile   string
	TerminalXIsolationAttestorPublicKeySHA256  string
	TerminalXEvidenceTTL                       time.Duration
	TerminalXDaytonaDaemonUID                  int
	TerminalXAgentUID                          int
}

func NewDockerClient(ctx context.Context, config DockerClientConfig) (*DockerClient, error) {
	logger := slog.Default().With(slog.String("component", "docker-client"))
	if config.Logger != nil {
		logger = config.Logger.With(slog.String("component", "docker-client"))
	}

	if config.DaemonStartTimeoutSec <= 0 {
		logger.Warn("Invalid daemon start timeout value. Using default value of 60 seconds")
		config.DaemonStartTimeoutSec = 60
	}

	if config.SandboxStartTimeoutSec <= 0 {
		logger.Warn("Invalid sandbox start timeout value. Using default value of 30 seconds")
		config.SandboxStartTimeoutSec = 30
	}

	// Android emulator cold boot can take well over a minute even on capable hosts,
	// so we allow a dedicated longer timeout for the ADB readiness probe.
	if config.AndroidBootTimeoutSec <= 0 {
		logger.Warn("Invalid android boot timeout value. Using default value of 300 seconds")
		config.AndroidBootTimeoutSec = 300
	}

	if config.BackupTimeoutMin <= 0 {
		logger.Warn("Invalid backup timeout value. Using default value of 60 minutes")
		config.BackupTimeoutMin = 60
	}

	var info system.Info
	err := utils.RetryWithExponentialBackoff(
		ctx,
		"get Docker info",
		8,
		1*time.Second,
		5*time.Second,
		func() error {
			var infoErr error
			info, infoErr = config.ApiClient.Info(ctx)
			return infoErr
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get Docker info: %w", err)
	}

	if !config.InterSandboxNetworkEnabled {
		if inspected, err := config.ApiClient.NetworkInspect(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.InspectOptions{}); err != nil {
			enableIPv4 := true
			enableIPv6 := false
			networkLabels := map[string]string{}
			if config.TerminalXHardened {
				networkLabels[terminalXNetworkProfileLabel] = terminalXHardenedProfileVersion
			}
			_, err := config.ApiClient.NetworkCreate(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.CreateOptions{
				Driver:     "bridge",
				Scope:      "local",
				EnableIPv4: &enableIPv4,
				EnableIPv6: &enableIPv6,
				Internal:   config.TerminalXHardened,
				Options: map[string]string{
					"com.docker.network.bridge.enable_icc": "false",
				},
				Labels: networkLabels,
				IPAM: &network.IPAM{
					Driver: "default",
					Config: []network.IPAMConfig{
						{Subnet: "172.20.0.0/16"},
					},
				},
			})

			if err != nil {
				return nil, fmt.Errorf("failed to create %s network: %w", RUNNER_BRIDGE_NETWORK_NAME, err)
			}
			if config.TerminalXHardened {
				inspected, err = config.ApiClient.NetworkInspect(ctx, RUNNER_BRIDGE_NETWORK_NAME, network.InspectOptions{})
				if err != nil {
					return nil, fmt.Errorf("failed to inspect %s network: %w", RUNNER_BRIDGE_NETWORK_NAME, err)
				}
				if err := validateTerminalXRunnerNetwork(inspected); err != nil {
					return nil, err
				}
			}
		} else if config.TerminalXHardened {
			if err := validateTerminalXRunnerNetwork(inspected); err != nil {
				return nil, err
			}
		}
	}

	filesystem := ""

	for _, driver := range info.DriverStatus {
		if driver[0] == "Backing Filesystem" {
			filesystem = driver[1]
			break
		}
	}

	if config.TerminalXHardened {
		if err := validateTerminalXRunnerRequirements(terminalXRunnerRequirements{
			imageID:                          config.TerminalXSandboxImageID,
			snapshotRef:                      config.TerminalXSandboxSnapshotRef,
			resourceLimitsDisabled:           config.ResourceLimitsDisabled,
			useSnapshotEntrypoint:            config.UseSnapshotEntrypoint,
			interSandboxNetworkEnabled:       config.InterSandboxNetworkEnabled,
			containerNetwork:                 config.ContainerNetwork,
			containerRuntime:                 config.ContainerRuntime,
			defaultRuntime:                   info.DefaultRuntime,
			cgroupVersion:                    info.CgroupVersion,
			gpuEnabled:                       config.GpuEnabled,
			mountKvm:                         config.MountKvmToAndroidSandbox,
			initializeDaemonTelemetry:        config.InitializeDaemonTelemetry,
			networkEnforcementAvailable:      config.NetRulesManager != nil,
			storageDriver:                    info.Driver,
			backingFilesystem:                filesystem,
			securityOptions:                  info.SecurityOptions,
			expectedDockerServerVersion:      config.TerminalXDockerServerVersion,
			actualDockerServerVersion:        info.ServerVersion,
			expectedContainerdCommit:         config.TerminalXContainerdCommit,
			actualContainerdCommit:           info.ContainerdCommit.ID,
			expectedRuncCommit:               config.TerminalXRuncCommit,
			actualRuncCommit:                 info.RuncCommit.ID,
			memoryLimitAvailable:             info.MemoryLimit,
			swapLimitAvailable:               info.SwapLimit,
			cpuQuotaAvailable:                info.CPUCfsPeriod && info.CPUCfsQuota,
			pidsLimitAvailable:               info.PidsLimit,
			oomKillAvailable:                 info.OomKillDisable,
			liveRestoreEnabled:               info.LiveRestoreEnabled,
			supervisorRelaySHA256:            config.TerminalXSupervisorRelaySHA256,
			assignmentBootstrapSHA256:        config.TerminalXAssignmentBootstrapSHA256,
			nodeSHA256:                       config.TerminalXNodeSHA256,
			deploymentBindingInstallerSHA256: config.TerminalXDeploymentBindingInstallerSHA256,
			isolationProbeSHA256:             config.TerminalXIsolationProbeSHA256,
		}); err != nil {
			return nil, err
		}
		if err := validateTerminalXAttestationRequirements(config); err != nil {
			return nil, err
		}
	}

	var deploymentBindingSigner *terminalXEd25519Signer
	var isolationAttestorSigner *terminalXEd25519Signer
	var bootstrapAuthorityPublicKey ed25519.PublicKey
	if config.TerminalXHardened {
		bootstrapAuthorityPublicKey, err = loadTerminalXEd25519PublicKey(
			config.TerminalXBootstrapAuthorityPublicKeyFile,
			config.TerminalXBootstrapAuthorityPublicKeySHA256,
			0,
		)
		if err != nil {
			return nil, err
		}
		deploymentBindingSigner, err = loadTerminalXEd25519Signer(
			config.TerminalXDeploymentBindingPrivateKeyFile,
			config.TerminalXDeploymentBindingKeyID,
			config.TerminalXDeploymentBindingPublicKeySHA256,
			0,
		)
		if err != nil {
			return nil, err
		}
		isolationAttestorSigner, err = loadTerminalXEd25519Signer(
			config.TerminalXIsolationAttestorPrivateKeyFile,
			config.TerminalXIsolationAttestorKeyID,
			config.TerminalXIsolationAttestorPublicKeySHA256,
			0,
		)
		if err != nil {
			deploymentBindingSigner.Close()
			return nil, err
		}
	}
	keepSignerSecrets := false
	defer func() {
		if !keepSignerSecrets {
			deploymentBindingSigner.Close()
			isolationAttestorSigner.Close()
		}
	}()

	gpuCount := 0
	gpuType := ""
	if config.GpuEnabled {
		gpuCount, gpuType = detectGpus(ctx)
		if gpuCount == 0 {
			logger.Warn("GPU_ENABLED=true but nvidia-smi did not report any GPUs; runner will not host GPU sandboxes")
		} else {
			logger.Info("Detected GPUs", "count", gpuCount, "type", gpuType)
		}
	}

	dockerClient := &DockerClient{
		apiClient:                          config.ApiClient,
		backupInfoCache:                    config.BackupInfoCache,
		pullTracker:                        &common.Tracker[string]{},
		logger:                             logger,
		awsRegion:                          config.AWSRegion,
		awsEndpointUrl:                     config.AWSEndpointUrl,
		awsAccessKeyId:                     config.AWSAccessKeyId,
		awsSecretAccessKey:                 config.AWSSecretAccessKey,
		volumeMutexes:                      make(map[string]*sync.Mutex),
		daemonPath:                         config.DaemonPath,
		computerUsePluginPath:              config.ComputerUsePluginPath,
		netRulesManager:                    config.NetRulesManager,
		resourceLimitsDisabled:             config.ResourceLimitsDisabled,
		daemonStartTimeoutSec:              config.DaemonStartTimeoutSec,
		sandboxStartTimeoutSec:             config.SandboxStartTimeoutSec,
		androidBootTimeoutSec:              config.AndroidBootTimeoutSec,
		useSnapshotEntrypoint:              config.UseSnapshotEntrypoint,
		volumeCleanupInterval:              config.VolumeCleanupInterval,
		volumeCleanupDryRun:                config.VolumeCleanupDryRun,
		volumeCleanupExclusionPeriod:       config.VolumeCleanupExclusionPeriod,
		backupTimeoutMin:                   config.BackupTimeoutMin,
		snapshotPullTimeout:                config.SnapshotPullTimeout,
		buildTimeoutMin:                    config.BuildTimeoutMin,
		buildCPUCores:                      config.BuildCPUCores,
		buildMemoryGB:                      config.BuildMemoryGB,
		initializeDaemonTelemetry:          config.InitializeDaemonTelemetry,
		interSandboxNetworkEnabled:         config.InterSandboxNetworkEnabled,
		gpuEnabled:                         config.GpuEnabled,
		gpuCount:                           gpuCount,
		gpuType:                            gpuType,
		gpuAllocator:                       newGpuAllocator(gpuCount),
		filesystem:                         filesystem,
		mountKvmToAndroidSandbox:           config.MountKvmToAndroidSandbox,
		terminalXHardened:                  config.TerminalXHardened,
		terminalXSandboxImageID:            config.TerminalXSandboxImageID,
		terminalXSandboxSnapshotRef:        config.TerminalXSandboxSnapshotRef,
		terminalXSupervisorRelaySHA256:     config.TerminalXSupervisorRelaySHA256,
		terminalXAssignmentBootstrapSHA256: config.TerminalXAssignmentBootstrapSHA256,
		terminalXNodeSHA256:                config.TerminalXNodeSHA256,
		terminalXDeploymentBindingInstallerSHA256: config.TerminalXDeploymentBindingInstallerSHA256,
		terminalXIsolationProbeSHA256:             config.TerminalXIsolationProbeSHA256,
		terminalXSandboxArtifactDigest:            config.TerminalXSandboxArtifactDigest,
		terminalXRunnerSourceCommit:               config.TerminalXRunnerSourceCommit,
		terminalXRunnerBinaryDigest:               config.TerminalXRunnerBinaryDigest,
		terminalXSeccompProfileSHA256:             config.TerminalXSeccompProfileSHA256,
		terminalXBootstrapAuthorityKeyID:          config.TerminalXBootstrapAuthorityKeyID,
		terminalXBootstrapAuthorityPublicKey:      bootstrapAuthorityPublicKey,
		terminalXDeploymentBindingSigner:          deploymentBindingSigner,
		terminalXIsolationAttestorSigner:          isolationAttestorSigner,
		terminalXEvidenceTTL:                      config.TerminalXEvidenceTTL,
		terminalXDaytonaDaemonUID:                 config.TerminalXDaytonaDaemonUID,
		terminalXAgentUID:                         config.TerminalXAgentUID,
		terminalXDockerVersion:                    info.ServerVersion,
		terminalXContainerdVersion:                info.ContainerdCommit.ID,
		terminalXClock:                            time.Now,
	}
	if dockerClient.terminalXHardened {
		if err := dockerClient.reconcileTerminalXContainers(ctx); err != nil {
			return nil, dockerClient.quarantineTerminalXContainers(ctx, err)
		}
	}
	keepSignerSecrets = true
	return dockerClient, nil
}

// GpuCount returns the number of NVIDIA GPUs detected on the host at startup.
// Returns 0 when GPU support is disabled or no GPU is present.
func (d *DockerClient) GpuCount() int {
	return d.gpuCount
}

// GpuType returns the human-readable name of the first GPU detected on the
// host at startup (e.g. "NVIDIA H100 80GB HBM3"). Returns "" when no GPU is
// present.
func (d *DockerClient) GpuType() string {
	return d.gpuType
}

func (d *DockerClient) ApiClient() client.APIClient {
	return d.apiClient
}

const RUNNER_BRIDGE_NETWORK_NAME = "runner-bridge"

type DockerClient struct {
	apiClient                                 client.APIClient
	backupInfoCache                           *cache.BackupInfoCache
	pullTracker                               *common.Tracker[string]
	logger                                    *slog.Logger
	awsRegion                                 string
	awsEndpointUrl                            string
	awsAccessKeyId                            string
	awsSecretAccessKey                        string
	volumeMutexes                             map[string]*sync.Mutex
	volumeMutexesMutex                        sync.Mutex
	daemonPath                                string
	computerUsePluginPath                     string
	netRulesManager                           *netrules.NetRulesManager
	resourceLimitsDisabled                    bool
	daemonStartTimeoutSec                     int
	sandboxStartTimeoutSec                    int
	androidBootTimeoutSec                     int
	useSnapshotEntrypoint                     bool
	volumeCleanupInterval                     time.Duration
	volumeCleanupDryRun                       bool
	volumeCleanupExclusionPeriod              time.Duration
	backupTimeoutMin                          int
	snapshotPullTimeout                       time.Duration
	buildTimeoutMin                           int
	buildCPUCores                             int64
	buildMemoryGB                             int64
	volumeCleanupMutex                        sync.Mutex
	lastVolumeCleanup                         time.Time
	initializeDaemonTelemetry                 bool
	filesystem                                string
	interSandboxNetworkEnabled                bool
	gpuEnabled                                bool
	gpuCount                                  int
	gpuType                                   string
	gpuAllocator                              *gpuAllocator
	mountKvmToAndroidSandbox                  bool
	terminalXHardened                         bool
	terminalXSandboxImageID                   string
	terminalXSandboxSnapshotRef               string
	terminalXSupervisorRelaySHA256            string
	terminalXAssignmentBootstrapSHA256        string
	terminalXNodeSHA256                       string
	terminalXDeploymentBindingInstallerSHA256 string
	terminalXIsolationProbeSHA256             string
	terminalXSandboxArtifactDigest            string
	terminalXRunnerSourceCommit               string
	terminalXRunnerBinaryDigest               string
	terminalXSeccompProfileSHA256             string
	terminalXBootstrapAuthorityKeyID          string
	terminalXBootstrapAuthorityPublicKey      ed25519.PublicKey
	terminalXDeploymentBindingSigner          *terminalXEd25519Signer
	terminalXIsolationAttestorSigner          *terminalXEd25519Signer
	terminalXEvidenceTTL                      time.Duration
	terminalXDaytonaDaemonUID                 int
	terminalXAgentUID                         int
	terminalXDockerVersion                    string
	terminalXContainerdVersion                string
	terminalXClock                            func() time.Time
	terminalXAssignmentBootstrapAdmission     terminalXOperationLimiter
	terminalXSupervisorRelayAdmission         terminalXOperationLimiter
	terminalXNetworkPolicyEnforcer            terminalXNetworkPolicyEnforcer
	terminalXAssignmentBootstrapPreflight     terminalXAssignmentBootstrapPreflight
	terminalXSupervisorRelayPreflight         terminalXSupervisorRelayPreflight
}

// CloseTerminalXSecrets irreversibly zeroes runner-host signing keys. It is
// idempotent and deliberately separate from the shared Docker API client,
// whose lifecycle remains owned by the runner process.
func (d *DockerClient) CloseTerminalXSecrets() {
	if d == nil {
		return
	}
	d.terminalXDeploymentBindingSigner.Close()
	d.terminalXIsolationAttestorSigner.Close()
}
