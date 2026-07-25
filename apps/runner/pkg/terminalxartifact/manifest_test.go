// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package terminalxartifact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/daytonaio/runner/pkg/terminalxidentity"
)

func TestManifestSchemaIsExactAndCanonical(t *testing.T) {
	manifest := Manifest{
		Artifacts: Artifacts{
			Daemon: Artifact{
				Architecture: Architecture, BinaryDigest: strings.Repeat("d", 64),
				OperatingSystem: OperatingSystem, SourceCommit: strings.Repeat("a", 40),
			},
			Runner: Artifact{
				Architecture: Architecture, BinaryDigest: strings.Repeat("e", 64),
				OperatingSystem: OperatingSystem, SourceCommit: strings.Repeat("a", 40),
			},
		},
		Kind: ManifestKind, Version: 1,
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"artifacts":{"daemon":{"architecture":"amd64","binaryDigest":"` + strings.Repeat("d", 64) +
		`","operatingSystem":"linux","sourceCommit":"` + strings.Repeat("a", 40) +
		`"},"runner":{"architecture":"amd64","binaryDigest":"` + strings.Repeat("e", 64) +
		`","operatingSystem":"linux","sourceCommit":"` + strings.Repeat("a", 40) +
		`"}},"kind":"terminalx.daytona-hardened-runtime-artifacts","version":1}`
	if string(encoded) != expected {
		t.Fatalf("runtime artifact manifest schema changed:\n%s", encoded)
	}
}

func TestReleaseIdentityValidationFailsClosed(t *testing.T) {
	valid := terminalxidentity.BinaryIdentity{
		Architecture: Architecture, BinaryDigest: strings.Repeat("a", 64),
		OperatingSystem: OperatingSystem, SourceCommit: strings.Repeat("b", 40),
	}
	if err := validateIdentity(valid, valid.SourceCommit); err != nil {
		t.Fatalf("valid artifact identity rejected: %v", err)
	}
	tests := map[string]func(*terminalxidentity.BinaryIdentity){
		"architecture":     func(value *terminalxidentity.BinaryIdentity) { value.Architecture = "arm64" },
		"operating system": func(value *terminalxidentity.BinaryIdentity) { value.OperatingSystem = "darwin" },
		"binary digest":    func(value *terminalxidentity.BinaryIdentity) { value.BinaryDigest = strings.Repeat("A", 64) },
		"source commit":    func(value *terminalxidentity.BinaryIdentity) { value.SourceCommit = strings.Repeat("c", 40) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if err := validateIdentity(candidate, valid.SourceCommit); err == nil {
				t.Fatal("mismatched artifact identity was accepted")
			}
		})
	}
}
