// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package terminalxidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

const testRevision = "f9b4dfe428d37f3d956acda4403879516aa8d923"

func cleanBuildInformation() *debug.BuildInfo {
	return &debug.BuildInfo{
		Main: debug.Module{Path: runnerModulePath},
		Settings: []debug.BuildSetting{
			{Key: "-buildmode", Value: "exe"},
			{Key: "vcs", Value: "git"},
			{Key: "vcs.revision", Value: testRevision},
			{Key: "vcs.modified", Value: "false"},
		},
	}
}

func TestExecutableMeasurementRequiresStableProtectedRegularBytes(t *testing.T) {
	path := t.TempDir() + "/executable"
	contents := []byte("stable executable bytes")
	if err := os.WriteFile(path, contents, 0o500); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	measured, err := measureOpenExecutable(file)
	file.Close()
	expected := sha256.Sum256(contents)
	if err != nil || measured.digest != hex.EncodeToString(expected[:]) {
		t.Fatalf("stable protected executable rejected: digest=%q err=%v", measured.digest, err)
	}
	if err := os.Chmod(path, 0o520); err != nil {
		t.Fatal(err)
	}
	file, err = os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = measureOpenExecutable(file)
	file.Close()
	if err == nil {
		t.Fatal("group-writable executable was accepted")
	}
}

func TestCleanSourceRevisionRequiresExactUnambiguousBuildIdentity(t *testing.T) {
	valid := cleanBuildInformation()
	if revision, err := CleanSourceRevision(valid, runnerModulePath); err != nil || revision != testRevision {
		t.Fatalf("clean build identity rejected: revision=%q err=%v", revision, err)
	}

	tests := map[string]func(*debug.BuildInfo){
		"wrong module": func(value *debug.BuildInfo) { value.Main.Path = "example.invalid/runner" },
		"missing vcs":  func(value *debug.BuildInfo) { value.Settings[1].Value = "" },
		"wrong vcs":    func(value *debug.BuildInfo) { value.Settings[1].Value = "hg" },
		"uppercase revision": func(value *debug.BuildInfo) {
			value.Settings[2].Value = strings.ToUpper(testRevision)
		},
		"short revision":     func(value *debug.BuildInfo) { value.Settings[2].Value = testRevision[:12] },
		"dirty":              func(value *debug.BuildInfo) { value.Settings[3].Value = "true" },
		"noncanonical clean": func(value *debug.BuildInfo) { value.Settings[3].Value = "False" },
		"duplicate revision": func(value *debug.BuildInfo) {
			value.Settings = append(value.Settings, debug.BuildSetting{Key: "vcs.revision", Value: testRevision})
		},
		"duplicate modified": func(value *debug.BuildInfo) {
			value.Settings = append(value.Settings, debug.BuildSetting{Key: "vcs.modified", Value: "false"})
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := cleanBuildInformation()
			mutate(candidate)
			if revision, err := CleanSourceRevision(candidate, runnerModulePath); err == nil || revision != "" {
				t.Fatalf("unsafe build identity accepted: %q", revision)
			}
		})
	}
	if revision, err := CleanSourceRevision(nil, runnerModulePath); err == nil || revision != "" {
		t.Fatal("missing build information was accepted")
	}
}

func TestInspectReleaseBinaryRejectsLinksAndNonGoArtifacts(t *testing.T) {
	file := t.TempDir() + "/artifact"
	if err := os.WriteFile(file, []byte("not a Go executable"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectReleaseBinary(file, runnerModulePath); err == nil {
		t.Fatal("non-Go release artifact was accepted")
	}
	link := t.TempDir() + "/artifact-link"
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectReleaseBinary(link, runnerModulePath); err == nil {
		t.Fatal("symlinked release artifact was accepted")
	}
}

func TestBuildPlatformRequiresExactUniqueSettings(t *testing.T) {
	valid := &debug.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "GOOS", Value: "linux"},
		{Key: "GOARCH", Value: "amd64"},
	}}
	operatingSystem, architecture, err := buildPlatform(valid)
	if err != nil || operatingSystem != "linux" || architecture != "amd64" {
		t.Fatalf("valid build platform rejected: %s/%s %v", operatingSystem, architecture, err)
	}
	for name, mutate := range map[string]func(*debug.BuildInfo){
		"missing operating system": func(value *debug.BuildInfo) { value.Settings[0].Value = "" },
		"missing architecture":     func(value *debug.BuildInfo) { value.Settings[1].Value = "" },
		"duplicate architecture": func(value *debug.BuildInfo) {
			value.Settings = append(value.Settings, debug.BuildSetting{Key: "GOARCH", Value: "amd64"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := &debug.BuildInfo{Settings: append([]debug.BuildSetting(nil), valid.Settings...)}
			mutate(candidate)
			if _, _, err := buildPlatform(candidate); err == nil {
				t.Fatal("ambiguous release platform was accepted")
			}
		})
	}
}
