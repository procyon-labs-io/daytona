// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

// Package terminalxartifact produces the exact deterministic manifest that
// binds hardened Daytona runner and daemon release bytes to their embedded VCS
// identities.
package terminalxartifact

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/daytonaio/runner/pkg/terminalxidentity"
)

const (
	ManifestKind     = "terminalx.daytona-hardened-runtime-artifacts"
	RunnerModulePath = "github.com/daytonaio/runner"
	DaemonModulePath = "github.com/daytonaio/daemon"
	OperatingSystem  = "linux"
	Architecture     = "amd64"
)

var (
	gitRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sha256Raw   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Artifact struct {
	Architecture    string `json:"architecture"`
	BinaryDigest    string `json:"binaryDigest"`
	OperatingSystem string `json:"operatingSystem"`
	SourceCommit    string `json:"sourceCommit"`
}

type Artifacts struct {
	Daemon Artifact `json:"daemon"`
	Runner Artifact `json:"runner"`
}

type Manifest struct {
	Artifacts Artifacts `json:"artifacts"`
	Kind      string    `json:"kind"`
	Version   int       `json:"version"`
}

// Generate inspects both binaries from stable non-symlink descriptors and
// emits one-line canonical JSON. Each binary must independently prove the
// exact expected clean source revision and linux/amd64 platform.
func Generate(runnerPath string, daemonPath string, expectedSourceCommit string) ([]byte, error) {
	if !gitRevision.MatchString(expectedSourceCommit) {
		return nil, fmt.Errorf("terminalx expected release source commit is invalid")
	}
	runner, err := terminalxidentity.InspectReleaseBinary(runnerPath, RunnerModulePath)
	if err != nil {
		return nil, err
	}
	daemon, err := terminalxidentity.InspectReleaseBinary(daemonPath, DaemonModulePath)
	if err != nil {
		return nil, err
	}
	if err := validateIdentity(runner, expectedSourceCommit); err != nil {
		return nil, fmt.Errorf("terminalx runner release identity does not match")
	}
	if err := validateIdentity(daemon, expectedSourceCommit); err != nil {
		return nil, fmt.Errorf("terminalx daemon release identity does not match")
	}
	manifest := Manifest{
		Artifacts: Artifacts{
			Daemon: artifactFromIdentity(daemon),
			Runner: artifactFromIdentity(runner),
		},
		Kind: ManifestKind, Version: 1,
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("terminalx runtime artifact manifest is unavailable")
	}
	return encoded, nil
}

func validateIdentity(identity terminalxidentity.BinaryIdentity, expectedSourceCommit string) error {
	if identity.OperatingSystem != OperatingSystem || identity.Architecture != Architecture ||
		identity.SourceCommit != expectedSourceCommit ||
		!sha256Raw.MatchString(identity.BinaryDigest) {
		return fmt.Errorf("terminalx release artifact identity is invalid")
	}
	return nil
}

func artifactFromIdentity(identity terminalxidentity.BinaryIdentity) Artifact {
	return Artifact{
		Architecture: identity.Architecture, BinaryDigest: identity.BinaryDigest,
		OperatingSystem: identity.OperatingSystem, SourceCommit: identity.SourceCommit,
	}
}
