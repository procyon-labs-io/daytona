// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package config

import "testing"

func TestValidateTerminalXProcessBoundaryFailsClosed(t *testing.T) {
	valid := func() Config {
		return Config{
			TerminalXHardened:         true,
			Environment:               "production",
			ApiLogRequests:            false,
			OtelLoggingEnabled:        false,
			OtelTracingEnabled:        false,
			InitializeDaemonTelemetry: false,
		}
	}
	validConfig := valid()
	if err := validConfig.ValidateTerminalXProcessBoundary(); err != nil {
		t.Fatalf("valid hardened process boundary rejected: %v", err)
	}

	tests := map[string]func(*Config){
		"development environment": func(config *Config) { config.Environment = "development" },
		"blank environment":       func(config *Config) { config.Environment = "" },
		"request logging":         func(config *Config) { config.ApiLogRequests = true },
		"otel logging":            func(config *Config) { config.OtelLoggingEnabled = true },
		"otel tracing":            func(config *Config) { config.OtelTracingEnabled = true },
		"otel endpoint":           func(config *Config) { config.OtelEndpoint = "https://collector.invalid" },
		"otel headers":            func(config *Config) { config.OtelHeaders = "authorization=secret" },
		"daemon telemetry":        func(config *Config) { config.InitializeDaemonTelemetry = true },
		"tcp Docker host":         func(config *Config) { config.DockerHostOverride = "tcp://127.0.0.1:2375" },
		"SSH Docker host":         func(config *Config) { config.DockerHostOverride = "ssh://docker@example.invalid" },
		"custom Unix Docker host": func(config *Config) { config.DockerHostOverride = "unix:///tmp/docker.sock" },
		"Docker API override":     func(config *Config) { config.DockerAPIVersionOverride = "1.47" },
		"Docker certificate path": func(config *Config) { config.DockerCertPathOverride = "/tmp/certs" },
		"Docker TLS override":     func(config *Config) { config.DockerTLSVerifyOverride = "1" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(&candidate)
			if err := candidate.ValidateTerminalXProcessBoundary(); err == nil {
				t.Fatal("unsafe hardened process boundary was accepted")
			}
		})
	}

	ordinary := valid()
	ordinary.TerminalXHardened = false
	ordinary.Environment = "development"
	ordinary.ApiLogRequests = true
	ordinary.OtelLoggingEnabled = true
	ordinary.OtelTracingEnabled = true
	ordinary.OtelEndpoint = "https://collector.invalid"
	ordinary.OtelHeaders = "authorization=secret"
	ordinary.InitializeDaemonTelemetry = true
	ordinary.DockerHostOverride = "tcp://127.0.0.1:2375"
	ordinary.DockerAPIVersionOverride = "1.47"
	ordinary.DockerCertPathOverride = "/tmp/certs"
	ordinary.DockerTLSVerifyOverride = "1"
	if err := ordinary.ValidateTerminalXProcessBoundary(); err != nil {
		t.Fatalf("ordinary Daytona runner behavior changed: %v", err)
	}
}
