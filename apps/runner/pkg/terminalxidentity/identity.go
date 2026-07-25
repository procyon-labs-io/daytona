// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

// Package terminalxidentity derives hardened-runner identity from Go's
// embedded VCS metadata and from bytes read through the live executable file
// descriptor. Operator configuration is never an identity source.
package terminalxidentity

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime/debug"

	"golang.org/x/sys/unix"
)

const (
	runnerModulePath          = "github.com/daytonaio/runner"
	maximumExecutableFileSize = int64(512 * 1024 * 1024)
)

var gitRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Identity is the immutable identity measured by a hardened runner before it
// initializes any provider or Docker integration.
type Identity struct {
	SourceCommit       string
	RunnerBinaryDigest string
}

// BinaryIdentity is a build-time measurement of a release binary. It is used
// by the release-manifest generator for runner and daemon artifacts.
type BinaryIdentity struct {
	Architecture    string
	BinaryDigest    string
	OperatingSystem string
	SourceCommit    string
}

type executableMeasurement struct {
	digest   string
	identity unix.Stat_t
}

// MeasureRunning derives the exact clean source revision from Go build info
// and hashes bytes opened through /proc/self/exe. It fails closed for local,
// dirty, non-Git, or -buildvcs=false builds.
func MeasureRunning() (Identity, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return Identity{}, fmt.Errorf("terminalx live runner executable is unavailable: %w", err)
	}
	measured, err := inspectOpenBinary(file, runnerModulePath)
	if closeErr := file.Close(); err == nil && closeErr != nil {
		err = closeErr
	}
	if err != nil {
		return Identity{}, fmt.Errorf("terminalx live runner executable measurement failed: %w", err)
	}
	return Identity{
		SourceCommit: measured.SourceCommit, RunnerBinaryDigest: measured.BinaryDigest,
	}, nil
}

// InspectReleaseBinary securely opens and measures a build artifact through a
// single non-symlink file descriptor, then validates the embedded module and
// clean VCS revision from the same bytes.
func InspectReleaseBinary(path string, expectedModulePath string) (BinaryIdentity, error) {
	if path == "" || expectedModulePath == "" {
		return BinaryIdentity{}, fmt.Errorf("terminalx release binary identity is invalid")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return BinaryIdentity{}, fmt.Errorf("terminalx release binary is unavailable: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return BinaryIdentity{}, fmt.Errorf("terminalx release binary is unavailable")
	}
	defer file.Close()
	return inspectOpenBinary(file, expectedModulePath)
}

func inspectOpenBinary(file *os.File, expectedModulePath string) (BinaryIdentity, error) {
	measured, err := measureOpenExecutable(file)
	if err != nil {
		return BinaryIdentity{}, fmt.Errorf("terminalx binary measurement failed: %w", err)
	}
	information, err := buildinfo.Read(file)
	if err != nil {
		return BinaryIdentity{}, fmt.Errorf("terminalx binary build identity is unavailable: %w", err)
	}
	revision, err := CleanSourceRevision(information, expectedModulePath)
	if err != nil {
		return BinaryIdentity{}, err
	}
	operatingSystem, architecture, err := buildPlatform(information)
	if err != nil {
		return BinaryIdentity{}, err
	}
	confirmed, err := measureOpenExecutable(file)
	if err != nil || confirmed.digest != measured.digest ||
		!sameFileIdentity(measured.identity, confirmed.identity) {
		return BinaryIdentity{}, fmt.Errorf("terminalx binary changed during identity inspection")
	}
	return BinaryIdentity{
		Architecture: architecture, BinaryDigest: measured.digest,
		OperatingSystem: operatingSystem, SourceCommit: revision,
	}, nil
}

func buildPlatform(information *debug.BuildInfo) (string, string, error) {
	if information == nil {
		return "", "", fmt.Errorf("terminalx binary platform identity is unavailable")
	}
	values := make(map[string]string, 2)
	for _, setting := range information.Settings {
		if setting.Key != "GOOS" && setting.Key != "GOARCH" {
			continue
		}
		if _, exists := values[setting.Key]; exists {
			return "", "", fmt.Errorf("terminalx binary platform identity is ambiguous")
		}
		values[setting.Key] = setting.Value
	}
	if values["GOOS"] == "" || values["GOARCH"] == "" {
		return "", "", fmt.Errorf("terminalx binary platform identity is unavailable")
	}
	return values["GOOS"], values["GOARCH"], nil
}

// CleanSourceRevision accepts exactly one clean Git revision from Go build
// settings. The main module path is part of the identity to prevent swapping a
// different Go executable carrying otherwise plausible VCS settings.
func CleanSourceRevision(information *debug.BuildInfo, expectedModulePath string) (string, error) {
	if information == nil || expectedModulePath == "" || information.Main.Path != expectedModulePath {
		return "", fmt.Errorf("terminalx binary main module identity is invalid")
	}
	values := make(map[string]string, 3)
	for _, setting := range information.Settings {
		switch setting.Key {
		case "vcs", "vcs.revision", "vcs.modified":
			if _, exists := values[setting.Key]; exists {
				return "", fmt.Errorf("terminalx binary VCS identity is ambiguous")
			}
			values[setting.Key] = setting.Value
		}
	}
	if values["vcs"] != "git" || values["vcs.modified"] != "false" ||
		!gitRevision.MatchString(values["vcs.revision"]) {
		return "", fmt.Errorf("terminalx binary requires an exact clean lowercase Git revision")
	}
	return values["vcs.revision"], nil
}

func measureOpenExecutable(file *os.File) (executableMeasurement, error) {
	if file == nil {
		return executableMeasurement{}, fmt.Errorf("executable file descriptor is unavailable")
	}
	var before unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil {
		return executableMeasurement{}, err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o111 == 0 || before.Mode&0o022 != 0 ||
		before.Size < 1 || before.Size > maximumExecutableFileSize {
		return executableMeasurement{}, fmt.Errorf("executable file identity is invalid")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableMeasurement{}, err
	}
	hash := sha256.New()
	read, err := io.Copy(hash, io.LimitReader(file, maximumExecutableFileSize+1))
	if err != nil {
		return executableMeasurement{}, err
	}
	if read != before.Size || read > maximumExecutableFileSize {
		return executableMeasurement{}, fmt.Errorf("executable file changed during measurement")
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &after); err != nil {
		return executableMeasurement{}, err
	}
	if !sameFileIdentity(before, after) {
		return executableMeasurement{}, fmt.Errorf("executable file changed during measurement")
	}
	return executableMeasurement{digest: hex.EncodeToString(hash.Sum(nil)), identity: after}, nil
}

func sameFileIdentity(left unix.Stat_t, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Mode == right.Mode &&
		left.Nlink == right.Nlink && left.Size == right.Size &&
		left.Mtim == right.Mtim && left.Ctim == right.Ctim
}
