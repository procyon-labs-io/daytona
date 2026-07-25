// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/pkg/stdcopy"
)

const (
	terminalXDeploymentBindingInstallerMaximumArtifactBytes int64 = 16 * 1024 * 1024
	terminalXDeploymentBindingMaximumBytes                  int64 = 128 * 1024
	terminalXDeploymentBindingInstallerMaximumStderrBytes   int64 = 4 * 1024
	terminalXDeploymentBindingInstallerTimeout                    = 10 * time.Second
)

var errTerminalXDeploymentBindingConflict = errors.New("terminalx deployment binding conflicts")

// installTerminalXDeploymentBinding takes ownership of binding and always
// zeroes it. The only executable selected is the digest-pinned image helper;
// its atomic file commit occurs before assignment bootstrap is invoked.
func (d *DockerClient) installTerminalXDeploymentBinding(
	ctx context.Context,
	containerID string,
	binding []byte,
) (returnErr error) {
	defer zeroTerminalXBytes(binding)
	if len(binding) < 2 || int64(len(binding)) > terminalXDeploymentBindingMaximumBytes {
		return fmt.Errorf("terminalx deployment binding is invalid")
	}
	installCtx, cancel := context.WithTimeout(ctx, terminalXDeploymentBindingInstallerTimeout)
	defer cancel()
	if err := d.verifyTerminalXDeploymentBindingInstaller(installCtx, containerID); err != nil {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	execResponse, err := d.apiClient.ContainerExecCreate(
		installCtx,
		containerID,
		terminalXDeploymentBindingInstallerExecOptions(),
	)
	if err != nil {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	attached, err := d.apiClient.ContainerExecAttach(installCtx, execResponse.ID, container.ExecStartOptions{
		Detach: false,
		Tty:    false,
	})
	if err != nil {
		return errors.Join(
			fmt.Errorf("terminalx deployment binding installer is unavailable"),
			d.ensureTerminalXExecTerminated(containerID, execResponse.ID),
		)
	}

	var closeOnce sync.Once
	closeAttached := func() { closeOnce.Do(func() { attached.Close() }) }
	stopCancellationClose := context.AfterFunc(installCtx, closeAttached)
	execTerminated := false
	defer func() {
		stopCancellationClose()
		closeAttached()
		if !execTerminated {
			returnErr = errors.Join(
				returnErr,
				d.ensureTerminalXExecTerminated(containerID, execResponse.ID),
			)
		}
	}()

	requestDone := make(chan error, 1)
	go func(request []byte) {
		_, copyErr := io.Copy(attached.Conn, bytes.NewReader(request))
		requestErr := errors.Join(copyErr, attached.CloseWrite())
		zeroTerminalXBytes(request)
		requestDone <- requestErr
	}(binding)
	binding = nil

	stdout := &terminalXBoundedBuffer{maximumBytes: 1}
	stderr := &terminalXBoundedBuffer{maximumBytes: terminalXDeploymentBindingInstallerMaximumStderrBytes}
	defer stdout.Zero()
	defer stderr.Zero()
	_, outputErr := stdcopy.StdCopy(stdout, stderr, attached.Reader)
	if outputErr != nil || installCtx.Err() != nil {
		closeAttached()
	}
	requestErr := <-requestDone
	if installCtx.Err() != nil {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	inspect, err := d.apiClient.ContainerExecInspect(installCtx, execResponse.ID)
	if err != nil || inspect.Running {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	execTerminated = true
	if outputErr != nil || requestErr != nil || stdout.Len() != 0 || stderr.Len() != 0 {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	if inspect.ExitCode == 73 {
		return errTerminalXDeploymentBindingConflict
	}
	if inspect.ExitCode != 0 {
		return fmt.Errorf("terminalx deployment binding installer is unavailable")
	}
	return nil
}

func terminalXDeploymentBindingInstallerExecOptions() container.ExecOptions {
	return container.ExecOptions{
		User:         "0:0",
		Privileged:   false,
		Tty:          false,
		AttachStdin:  true,
		AttachStderr: true,
		AttachStdout: true,
		WorkingDir:   "/",
		Cmd:          []string{terminalXDeploymentBindingInstallerPath},
	}
}

func (d *DockerClient) verifyTerminalXDeploymentBindingInstaller(
	ctx context.Context,
	containerID string,
) error {
	return d.verifyTerminalXRootExecutionBoundary(
		ctx,
		containerID,
		terminalXDeploymentBindingInstallerPath,
		terminalXDeploymentBindingInstallerMaximumArtifactBytes,
		d.terminalXDeploymentBindingInstallerSHA256,
	)
}
