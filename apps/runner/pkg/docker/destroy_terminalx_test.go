// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

type terminalXDestroyAPIFake struct {
	client.APIClient
	containerInspectCalls int
	networkInspectCalls   int
}

func (fake *terminalXDestroyAPIFake) ContainerInspect(
	context.Context,
	string,
) (container.InspectResponse, error) {
	fake.containerInspectCalls++
	return container.InspectResponse{}, errdefs.ErrNotFound
}

func (fake *terminalXDestroyAPIFake) NetworkInspect(
	context.Context,
	string,
	network.InspectOptions,
) (network.Inspect, error) {
	fake.networkInspectCalls++
	return network.Inspect{}, errdefs.ErrNotFound
}

func TestTerminalXDestroyRejectsUnboundIdentityBeforeAnyDockerOrNetworkEffect(t *testing.T) {
	fake := &terminalXDestroyAPIFake{}
	dockerClient := &DockerClient{apiClient: fake, terminalXHardened: true}
	if err := dockerClient.Destroy(t.Context(), "../../victim"); err == nil {
		t.Fatal("unsafe hardened destroy identity accepted")
	}
	if fake.containerInspectCalls != 0 || fake.networkInspectCalls != 0 {
		t.Fatalf("invalid destroy produced side effects: inspect=%d network=%d",
			fake.containerInspectCalls, fake.networkInspectCalls)
	}
}

func TestTerminalXDestroyNotFoundNeverTouchesLegacyLinkNetwork(t *testing.T) {
	fake := &terminalXDestroyAPIFake{}
	dockerClient := &DockerClient{apiClient: fake, terminalXHardened: true}
	if err := dockerClient.Destroy(t.Context(), testTerminalXSandboxUUID); err != nil {
		t.Fatalf("idempotent hardened destroy failed: %v", err)
	}
	if fake.containerInspectCalls != 1 || fake.networkInspectCalls != 0 {
		t.Fatalf("hardened not-found destroy effects: inspect=%d network=%d",
			fake.containerInspectCalls, fake.networkInspectCalls)
	}
}
