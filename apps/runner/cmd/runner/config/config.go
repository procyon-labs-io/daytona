// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/kelseyhightower/envconfig"
	"github.com/vishvananda/netlink"
)

type Config struct {
	DaytonaApiUrl                      string        `envconfig:"DAYTONA_API_URL"`
	ApiToken                           string        `envconfig:"DAYTONA_RUNNER_TOKEN"`
	ApiPort                            int           `envconfig:"API_PORT"`
	ApiLogRequests                     bool          `envconfig:"API_LOG_REQUESTS" default:"false"`
	TLSCertFile                        string        `envconfig:"TLS_CERT_FILE"`
	TLSKeyFile                         string        `envconfig:"TLS_KEY_FILE"`
	EnableTLS                          bool          `envconfig:"ENABLE_TLS"`
	OtelLoggingEnabled                 bool          `envconfig:"OTEL_LOGGING_ENABLED"`
	OtelTracingEnabled                 bool          `envconfig:"OTEL_TRACING_ENABLED"`
	OtelEndpoint                       string        `envconfig:"OTEL_EXPORTER_OTLP_ENDPOINT"`
	OtelHeaders                        string        `envconfig:"OTEL_EXPORTER_OTLP_HEADERS"`
	DockerHostOverride                 string        `envconfig:"DOCKER_HOST"`
	DockerAPIVersionOverride           string        `envconfig:"DOCKER_API_VERSION"`
	DockerCertPathOverride             string        `envconfig:"DOCKER_CERT_PATH"`
	DockerTLSVerifyOverride            string        `envconfig:"DOCKER_TLS_VERIFY"`
	BackupInfoCacheRetention           time.Duration `envconfig:"BACKUP_INFO_CACHE_RETENTION" default:"168h" validate:"min=5m"`
	Environment                        string        `envconfig:"ENVIRONMENT"`
	ContainerRuntime                   string        `envconfig:"CONTAINER_RUNTIME"`
	ContainerNetwork                   string        `envconfig:"CONTAINER_NETWORK"`
	InterSandboxNetworkEnabled         bool          `envconfig:"INTER_SANDBOX_NETWORK_ENABLED" default:"true"`
	GpuEnabled                         bool          `envconfig:"GPU_ENABLED" default:"false"`
	LogFilePath                        string        `envconfig:"LOG_FILE_PATH"`
	AWSRegion                          string        `envconfig:"AWS_REGION"`
	AWSEndpointUrl                     string        `envconfig:"AWS_ENDPOINT_URL"`
	AWSAccessKeyId                     string        `envconfig:"AWS_ACCESS_KEY_ID"`
	AWSSecretAccessKey                 string        `envconfig:"AWS_SECRET_ACCESS_KEY"`
	AWSDefaultBucket                   string        `envconfig:"AWS_DEFAULT_BUCKET"`
	ResourceLimitsDisabled             bool          `envconfig:"RESOURCE_LIMITS_DISABLED"`
	DaemonStartTimeoutSec              int           `envconfig:"DAEMON_START_TIMEOUT_SEC"`
	SandboxStartTimeoutSec             int           `envconfig:"SANDBOX_START_TIMEOUT_SEC"`
	AndroidBootTimeoutSec              int           `envconfig:"ANDROID_BOOT_TIMEOUT_SEC"`
	UseSnapshotEntrypoint              bool          `envconfig:"USE_SNAPSHOT_ENTRYPOINT"`
	Domain                             string        `envconfig:"RUNNER_DOMAIN" validate:"omitempty,hostname|ip"`
	VolumeCleanupInterval              time.Duration `envconfig:"VOLUME_CLEANUP_INTERVAL" default:"30s" validate:"min=10s"`
	VolumeCleanupDryRun                bool          `envconfig:"VOLUME_CLEANUP_DRY_RUN" default:"true"`
	VolumeCleanupExclusionPeriod       time.Duration `envconfig:"VOLUME_CLEANUP_EXCLUSION_PERIOD" default:"120s" validate:"min=0s"`
	PollTimeout                        time.Duration `envconfig:"POLL_TIMEOUT" default:"30s"`
	PollLimit                          int           `envconfig:"POLL_LIMIT" default:"10" validate:"min=1,max=100"`
	CollectorWindowSize                int           `envconfig:"COLLECTOR_WINDOW_SIZE" default:"60" validate:"min=1"`
	CPUUsageSnapshotInterval           time.Duration `envconfig:"CPU_USAGE_SNAPSHOT_INTERVAL" default:"5s" validate:"min=1s"`
	AllocatedResourcesSnapshotInterval time.Duration `envconfig:"ALLOCATED_RESOURCES_SNAPSHOT_INTERVAL" default:"5s" validate:"min=1s"`
	HealthcheckInterval                time.Duration `envconfig:"HEALTHCHECK_INTERVAL" default:"30s" validate:"min=10s"`
	HealthcheckTimeout                 time.Duration `envconfig:"HEALTHCHECK_TIMEOUT" default:"10s"`
	BackupTimeoutMin                   int           `envconfig:"BACKUP_TIMEOUT_MIN" default:"60" validate:"min=1"`
	SnapshotPullTimeout                time.Duration `envconfig:"SNAPSHOT_PULL_TIMEOUT" default:"60m" validate:"min=1m"`
	BuildTimeoutMin                    int           `envconfig:"BUILD_TIMEOUT_MIN" default:"120" validate:"min=1"`
	BuildCPUCores                      int64         `envconfig:"BUILD_CPU_CORES" default:"4" validate:"min=1"`
	BuildMemoryGB                      int64         `envconfig:"BUILD_MEMORY_GB" default:"8" validate:"min=1"`
	ApiVersion                         int           `envconfig:"API_VERSION" default:"2"`
	InitializeDaemonTelemetry          bool          `envconfig:"INITIALIZE_DAEMON_TELEMETRY" default:"true"`
	SnapshotErrorCacheRetention        time.Duration `envconfig:"SNAPSHOT_ERROR_CACHE_RETENTION" default:"10m" validate:"min=5m"`
	BuildEngine                        string        `envconfig:"BUILD_ENGINE" default:"buildkit" validate:"oneof=buildkit legacy"`
	ForceSnapshotRemoval               bool          `envconfig:"FORCE_SNAPSHOT_REMOVAL" default:"true"`
	MountKvmToAndroidSandbox           bool          `envconfig:"MOUNT_KVM_TO_ANDROID_SANDBOX" default:"false"`
	// TerminalXHardened enables the fail-closed runner profile used by the
	// TerminalX hosted Runtime.  It is deliberately opt-in so an operator must
	// acknowledge that this runner accepts only the pinned TerminalX image and
	// its much narrower Sandbox contract.
	TerminalXHardened                          bool          `envconfig:"TERMINALX_HARDENED" default:"false"`
	TerminalXSandboxImageID                    string        `envconfig:"TERMINALX_SANDBOX_IMAGE_ID"`
	TerminalXSandboxSnapshotRef                string        `envconfig:"TERMINALX_SANDBOX_SNAPSHOT_REF"`
	TerminalXDockerServerVersion               string        `envconfig:"TERMINALX_DOCKER_SERVER_VERSION"`
	TerminalXContainerdCommit                  string        `envconfig:"TERMINALX_CONTAINERD_COMMIT"`
	TerminalXRuncCommit                        string        `envconfig:"TERMINALX_RUNC_COMMIT"`
	TerminalXSupervisorRelaySHA256             string        `envconfig:"TERMINALX_SUPERVISOR_RELAY_SHA256"`
	TerminalXAssignmentBootstrapSHA256         string        `envconfig:"TERMINALX_ASSIGNMENT_BOOTSTRAP_SHA256"`
	TerminalXNodeSHA256                        string        `envconfig:"TERMINALX_NODE_SHA256"`
	TerminalXDeploymentBindingInstallerSHA256  string        `envconfig:"TERMINALX_DEPLOYMENT_BINDING_INSTALLER_SHA256"`
	TerminalXIsolationProbeSHA256              string        `envconfig:"TERMINALX_ISOLATION_PROBE_SHA256"`
	TerminalXSandboxArtifactDigest             string        `envconfig:"TERMINALX_SANDBOX_ARTIFACT_DIGEST"`
	TerminalXHardenedSourceCommit              string        `envconfig:"TERMINALX_HARDENED_SOURCE_COMMIT"`
	TerminalXSeccompProfileSHA256              string        `envconfig:"TERMINALX_SECCOMP_PROFILE_SHA256"`
	TerminalXBootstrapAuthorityKeyID           string        `envconfig:"TERMINALX_BOOTSTRAP_AUTHORITY_KEY_ID"`
	TerminalXBootstrapAuthorityPublicKeyFile   string        `envconfig:"TERMINALX_BOOTSTRAP_AUTHORITY_PUBLIC_KEY_FILE"`
	TerminalXBootstrapAuthorityPublicKeySHA256 string        `envconfig:"TERMINALX_BOOTSTRAP_AUTHORITY_PUBLIC_KEY_SHA256"`
	TerminalXDeploymentBindingKeyID            string        `envconfig:"TERMINALX_DEPLOYMENT_BINDING_KEY_ID"`
	TerminalXDeploymentBindingPrivateKeyFile   string        `envconfig:"TERMINALX_DEPLOYMENT_BINDING_PRIVATE_KEY_FILE"`
	TerminalXDeploymentBindingPublicKeySHA256  string        `envconfig:"TERMINALX_DEPLOYMENT_BINDING_PUBLIC_KEY_SHA256"`
	TerminalXIsolationAttestorKeyID            string        `envconfig:"TERMINALX_ISOLATION_ATTESTOR_KEY_ID"`
	TerminalXIsolationAttestorPrivateKeyFile   string        `envconfig:"TERMINALX_ISOLATION_ATTESTOR_PRIVATE_KEY_FILE"`
	TerminalXIsolationAttestorPublicKeySHA256  string        `envconfig:"TERMINALX_ISOLATION_ATTESTOR_PUBLIC_KEY_SHA256"`
	TerminalXEvidenceTTL                       time.Duration `envconfig:"TERMINALX_EVIDENCE_TTL" default:"60s" validate:"min=1s,max=5m"`
	TerminalXDaytonaDaemonUID                  int           `envconfig:"TERMINALX_DAYTONA_DAEMON_UID" default:"10001" validate:"eq=10001"`
	TerminalXAgentUID                          int           `envconfig:"TERMINALX_AGENT_UID" default:"10001" validate:"eq=10001"`
}

var DEFAULT_API_PORT int = 8080

var config *Config

func GetConfig() (*Config, error) {
	if config != nil {
		return config, nil
	}

	config = &Config{}

	err := envconfig.Process("", config)
	if err != nil {
		return nil, err
	}

	var validate = validator.New()
	err = validate.Struct(config)
	if err != nil {
		return nil, err
	}

	if config.DaytonaApiUrl == "" {
		// For backward compatibility
		serverUrl := os.Getenv("SERVER_URL")
		if serverUrl == "" {
			return nil, fmt.Errorf("DAYTONA_API_URL or SERVER_URL is required")
		}
		config.DaytonaApiUrl = serverUrl
	}

	if config.ApiToken == "" {
		// For backward compatibility
		apiToken := os.Getenv("API_TOKEN")
		if apiToken == "" {
			return nil, fmt.Errorf("DAYTONA_RUNNER_TOKEN or API_TOKEN is required")
		}
		config.ApiToken = apiToken
	}

	if config.ApiPort == 0 {
		config.ApiPort = DEFAULT_API_PORT
	}

	if config.Domain == "" {
		ip, err := getOutboundIP()
		if err != nil {
			return nil, err
		}
		config.Domain = ip.String()
	}

	return config, nil
}

func (c *Config) GetOtelHeaders() map[string]string {
	headers := map[string]string{}
	for _, pair := range strings.Split(c.OtelHeaders, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		k, v, found := strings.Cut(pair, "=")
		if !found {
			continue
		}

		headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}

	return headers
}

// ValidateTerminalXProcessBoundary rejects observability and development
// options that could disclose provider-private Sandbox identifiers outside the
// hardened runner host. This check must run before any telemetry exporter is
// initialized.
func (c *Config) ValidateTerminalXProcessBoundary() error {
	if !c.TerminalXHardened {
		return nil
	}
	if c.Environment != "production" {
		return fmt.Errorf("TerminalX hardened runner requires ENVIRONMENT=production")
	}
	if c.ApiLogRequests {
		return fmt.Errorf("TerminalX hardened runner requires API_LOG_REQUESTS=false")
	}
	if c.OtelLoggingEnabled || c.OtelTracingEnabled ||
		strings.TrimSpace(c.OtelEndpoint) != "" || strings.TrimSpace(c.OtelHeaders) != "" {
		return fmt.Errorf("TerminalX hardened runner does not permit OpenTelemetry exporters")
	}
	if c.InitializeDaemonTelemetry {
		return fmt.Errorf("TerminalX hardened runner requires INITIALIZE_DAEMON_TELEMETRY=false")
	}
	if strings.TrimSpace(c.DockerHostOverride) != "" ||
		strings.TrimSpace(c.DockerAPIVersionOverride) != "" ||
		strings.TrimSpace(c.DockerCertPathOverride) != "" ||
		strings.TrimSpace(c.DockerTLSVerifyOverride) != "" {
		return fmt.Errorf("TerminalX hardened runner does not permit Docker client environment overrides")
	}
	return nil
}

func GetContainerRuntime() string {
	return config.ContainerRuntime
}

func GetContainerNetwork() string {
	return config.ContainerNetwork
}

func GetEnvironment() string {
	return config.Environment
}

func GetBuildEngine() string {
	return config.BuildEngine
}

func GetForceSnapshotRemoval() bool {
	return config.ForceSnapshotRemoval
}

func GetBuildLogFilePath(snapshotRef string) (string, error) {
	// Extract image name from various snapshot ref formats:
	// - registry:5000/daytona/daytona-<hash>
	// - daytona-<hash>
	// - daytona-<hash>:tag
	// - cr.preprod.daytona.io/sbox/daytona/daytona-<hash>:daytona

	buildId := snapshotRef

	// Remove tag if present (everything after last colon that's not part of a port)
	// A tag colon will come after the last slash
	lastSlashIndex := strings.LastIndex(buildId, "/")
	lastColonIndex := strings.LastIndex(buildId, ":")

	if lastColonIndex > lastSlashIndex && lastColonIndex != -1 {
		// This colon is a tag separator, not a port separator
		buildId = buildId[:lastColonIndex]
	}

	// Extract the image name (last component after the last slash)
	if lastSlashIndex := strings.LastIndex(buildId, "/"); lastSlashIndex != -1 {
		buildId = buildId[lastSlashIndex+1:]
	}

	c, err := GetConfig()
	if err != nil {
		return "", err
	}

	logPath := filepath.Join(filepath.Dir(c.LogFilePath), "builds", buildId)

	if err := os.MkdirAll(filepath.Dir(logPath), 0755); err != nil {
		return "", fmt.Errorf("failed to create log directory: %w", err)
	}

	if _, err := os.OpenFile(logPath, os.O_CREATE, 0644); err != nil {
		return "", fmt.Errorf("failed to create log file: %w", err)
	}

	return logPath, nil
}

// getOutboundIP returns the IP address of the default route's network interface
func getOutboundIP() (net.IP, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list routes: %w", err)
	}

	// Find the default route (destination 0.0.0.0/0)
	for _, route := range routes {
		if route.Dst == nil || route.Dst.IP.Equal(net.IPv4zero) {
			// Get the link (interface) for this route
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				return nil, fmt.Errorf("failed to get link: %w", err)
			}

			// Get addresses for this interface
			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				return nil, fmt.Errorf("failed to get addresses: %w", err)
			}

			if len(addrs) > 0 {
				return addrs[0].IP, nil
			}
		}
	}

	return nil, fmt.Errorf("no default route found")
}
