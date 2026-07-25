// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
)

const terminalXExecCleanupTimeout = 5 * time.Second

type terminalXNetworkPolicyEnforcer func(context.Context, *container.InspectResponse) error

func wipeTerminalXRootExecInput(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (d *DockerClient) enforceTerminalXRootExecNetworkPolicy(
	ctx context.Context,
	containerInfo *container.InspectResponse,
) error {
	if d.terminalXNetworkPolicyEnforcer != nil {
		return d.terminalXNetworkPolicyEnforcer(ctx, containerInfo)
	}
	return d.enforceTerminalXNetworkPolicy(ctx, containerInfo)
}

// Docker has no per-exec kill API. If closing a hijacked attachment does not
// prove that a fixed root exec terminated, the only safe fallback is to kill
// its Sandbox and, if that fails, quarantine the dedicated runner.
func (d *DockerClient) ensureTerminalXExecTerminated(containerID string, execID string) error {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), terminalXExecCleanupTimeout)
	defer cancel()
	if d.terminalXExecIsStopped(cleanupCtx, containerID, execID) {
		return nil
	}
	cause := fmt.Errorf("terminalx fixed root exec termination was not observed")
	if err := d.apiClient.ContainerKill(cleanupCtx, containerID, "KILL"); err != nil {
		quarantineCtx, quarantineCancel := context.WithTimeout(context.Background(), terminalXExecCleanupTimeout)
		defer quarantineCancel()
		return d.quarantineTerminalXContainers(
			quarantineCtx,
			errors.Join(cause, fmt.Errorf("terminalx sandbox quarantine failed: %w", err)),
		)
	}

	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		if d.terminalXExecIsStopped(cleanupCtx, containerID, execID) {
			return cause
		}
		select {
		case <-cleanupCtx.Done():
			quarantineCtx, quarantineCancel := context.WithTimeout(context.Background(), terminalXExecCleanupTimeout)
			defer quarantineCancel()
			return d.quarantineTerminalXContainers(quarantineCtx, errors.Join(cause, cleanupCtx.Err()))
		case <-ticker.C:
		}
	}
}

func (d *DockerClient) terminalXExecIsStopped(
	ctx context.Context,
	containerID string,
	execID string,
) bool {
	if inspected, err := d.apiClient.ContainerExecInspect(ctx, execID); err == nil && !inspected.Running {
		return true
	}
	container, err := d.apiClient.ContainerInspect(ctx, containerID)
	return err == nil && container.State != nil && !container.State.Running
}
