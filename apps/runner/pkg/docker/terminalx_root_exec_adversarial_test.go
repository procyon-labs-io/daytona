// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sync"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type terminalXRootBoundaryAPIClient struct {
	client.APIClient

	mu           sync.Mutex
	containerIDs []string
	paths        []string
	payloads     map[string][]byte
}

func (fake *terminalXRootBoundaryAPIClient) CopyFromContainer(
	_ context.Context,
	containerID string,
	sourcePath string,
) (io.ReadCloser, container.PathStat, error) {
	fake.mu.Lock()
	fake.containerIDs = append(fake.containerIDs, containerID)
	fake.paths = append(fake.paths, sourcePath)
	fake.mu.Unlock()

	if payload, ok := fake.payloads[sourcePath]; ok {
		archive, stat := terminalXTestExecutableArchive(sourcePath, payload)
		return io.NopCloser(archive), stat, nil
	}
	archive, stat := terminalXTestDirectoryArchive(sourcePath)
	return io.NopCloser(archive), stat, nil
}

func terminalXTestExecutableArchive(executablePath string, payload []byte) (*bytes.Reader, container.PathStat) {
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	_ = writer.WriteHeader(&tar.Header{
		Name:     path.Base(executablePath),
		Mode:     0o555,
		Uid:      0,
		Gid:      0,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	})
	_, _ = writer.Write(payload)
	_ = writer.Close()
	return bytes.NewReader(output.Bytes()), container.PathStat{
		Name: path.Base(executablePath),
		Size: int64(len(payload)),
		Mode: 0o555,
	}
}

func terminalXTestDirectoryArchive(directory string) (*bytes.Reader, container.PathStat) {
	name := path.Base(directory)
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	_ = writer.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o755,
		Uid:      0,
		Gid:      0,
		Typeflag: tar.TypeDir,
	})
	_ = writer.Close()
	return bytes.NewReader(output.Bytes()), container.PathStat{
		Name: name,
		Mode: os.ModeDir | 0o755,
	}
}

func terminalXTestSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func TestVerifyTerminalXRootExecutionBoundaryPinsCanonicalContainerNodeLeafAndParentChain(t *testing.T) {
	t.Parallel()
	const canonicalID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	nodePayload := []byte("pinned-node-interpreter")
	relayPayload := []byte("pinned-supervisor-relay")
	fake := &terminalXRootBoundaryAPIClient{payloads: map[string][]byte{
		terminalXNodePath:            nodePayload,
		terminalXSupervisorRelayPath: relayPayload,
	}}
	dockerClient := &DockerClient{
		apiClient:                      fake,
		terminalXNodeSHA256:            terminalXTestSHA256(nodePayload),
		terminalXSupervisorRelaySHA256: terminalXTestSHA256(relayPayload),
	}

	if err := dockerClient.verifyTerminalXSupervisorRelay(t.Context(), canonicalID); err != nil {
		t.Fatalf("valid root execution boundary rejected: %v", err)
	}

	wantPaths := []string{
		"/", "/usr", "/usr/local", "/usr/local/bin",
		"/usr/local/libexec", "/usr/local/libexec/terminalx",
		terminalXNodePath,
		terminalXSupervisorRelayPath,
		"/", "/usr", "/usr/local", "/usr/local/bin",
		"/usr/local/libexec", "/usr/local/libexec/terminalx",
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !slices.Equal(fake.paths, wantPaths) {
		t.Fatalf("measured paths = %v, want %v", fake.paths, wantPaths)
	}
	if len(fake.containerIDs) != len(wantPaths) {
		t.Fatalf("measured container IDs = %d, want %d", len(fake.containerIDs), len(wantPaths))
	}
	for index, got := range fake.containerIDs {
		if got != canonicalID {
			t.Fatalf("measurement %d used container %q, want canonical %q", index, got, canonicalID)
		}
	}
}

func TestVerifyTerminalXRootExecutionBoundaryFailsBeforeExecWhenAnyChainNodeOrLeafDrifts(t *testing.T) {
	t.Parallel()
	const canonicalID = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	nodePayload := []byte("pinned-node-interpreter")
	bootstrapPayload := []byte("pinned-assignment-bootstrap")

	for _, corruptPath := range []string{
		"/",
		"/usr/local/bin",
		"/usr/local/libexec/terminalx",
		terminalXNodePath,
		terminalXAssignmentBootstrapPath,
	} {
		corruptPath := corruptPath
		t.Run(fmt.Sprintf("drift_%x", sha256.Sum256([]byte(corruptPath)))[:18], func(t *testing.T) {
			t.Parallel()
			fake := &terminalXCorruptRootBoundaryAPIClient{
				terminalXRootBoundaryAPIClient: terminalXRootBoundaryAPIClient{payloads: map[string][]byte{
					terminalXNodePath:                nodePayload,
					terminalXAssignmentBootstrapPath: bootstrapPayload,
				}},
				corruptPath: corruptPath,
			}
			dockerClient := &DockerClient{
				apiClient:                          fake,
				terminalXNodeSHA256:                terminalXTestSHA256(nodePayload),
				terminalXAssignmentBootstrapSHA256: terminalXTestSHA256(bootstrapPayload),
			}
			if err := dockerClient.verifyTerminalXAssignmentBootstrap(t.Context(), canonicalID); err == nil {
				t.Fatalf("root boundary accepted drift at %s", corruptPath)
			}
		})
	}
}

type terminalXCorruptRootBoundaryAPIClient struct {
	terminalXRootBoundaryAPIClient
	corruptPath string
}

func (fake *terminalXCorruptRootBoundaryAPIClient) CopyFromContainer(
	ctx context.Context,
	containerID string,
	sourcePath string,
) (io.ReadCloser, container.PathStat, error) {
	archive, stat, err := fake.terminalXRootBoundaryAPIClient.CopyFromContainer(ctx, containerID, sourcePath)
	if err != nil || sourcePath != fake.corruptPath {
		return archive, stat, err
	}
	_ = archive.Close()
	if stat.Mode.IsDir() {
		candidate, candidateStat := terminalXTestDirectoryArchive(sourcePath)
		candidateStat.Mode = os.ModeDir | 0o775
		return io.NopCloser(candidate), candidateStat, nil
	}
	payload := append(bytes.Clone(fake.payloads[sourcePath]), byte('!'))
	candidate, candidateStat := terminalXTestExecutableArchive(sourcePath, payload)
	return io.NopCloser(candidate), candidateStat, nil
}
