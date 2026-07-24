// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/daytonaio/common-go/pkg/log"
	"github.com/daytonaio/common-go/pkg/timer"
	"github.com/daytonaio/runner/pkg/api/dto"

	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/pkg/jsonmessage"
)

func (d *DockerClient) PullImage(ctx context.Context, imageName string, reg *dto.RegistryDTO, sandboxId *string) (*image.InspectResponse, error) {
	defer timer.Timer()()
	if d.terminalXHardened {
		if imageName != d.terminalXSandboxSnapshotRef || sandboxId == nil {
			return nil, fmt.Errorf("terminalx hardened runner accepts only its preloaded pinned image")
		}
		inspected, err := d.apiClient.ImageInspect(ctx, d.terminalXSandboxSnapshotRef)
		if err != nil {
			return nil, fmt.Errorf("terminalx hardened sandbox image is not preloaded: %w", err)
		}
		if err := validateTerminalXImage(&inspected, d.terminalXSandboxImageID); err != nil {
			return nil, err
		}
		return &inspected, nil
	}

	tag := "latest"
	lastColonIndex := strings.LastIndex(imageName, ":")
	if lastColonIndex != -1 {
		tag = imageName[lastColonIndex+1:]
	}

	if tag != "latest" {
		inspect, err := d.apiClient.ImageInspect(ctx, imageName)
		if err == nil {
			return &inspect, nil
		}
	}

	d.logger.InfoContext(ctx, "Pulling image", "imageName", imageName)

	if sandboxId != nil {
		d.pullTracker.Add(*sandboxId)
		defer d.pullTracker.Remove(*sandboxId)
	}

	responseBody, err := d.apiClient.ImagePull(ctx, imageName, image.PullOptions{
		RegistryAuth: getRegistryAuth(reg),
		Platform:     "linux/amd64",
	})
	if err != nil {
		return nil, err
	}
	defer responseBody.Close()

	err = jsonmessage.DisplayJSONMessagesStream(responseBody, io.Writer(&log.DebugLogWriter{}), 0, true, nil)
	if err != nil {
		return nil, err
	}

	d.logger.InfoContext(ctx, "Image pulled successfully", "imageName", imageName)

	inspect, err := d.apiClient.ImageInspect(ctx, imageName)
	if err != nil {
		return nil, err
	}

	return &inspect, nil
}

func getRegistryAuth(reg *dto.RegistryDTO) string {
	if reg == nil || !reg.HasAuth() {
		// Sometimes registry auth fails if "" is sent, so sending "empty" instead
		return "empty"
	}

	authConfig := registry.AuthConfig{
		Username: *reg.Username,
		Password: *reg.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		// Sometimes registry auth fails if "" is sent, so sending "empty" instead
		return "empty"
	}

	return base64.URLEncoding.EncodeToString(encodedJSON)
}
