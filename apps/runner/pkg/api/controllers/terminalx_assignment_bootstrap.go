// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"net/http"
	"strings"

	terminalxdocker "github.com/daytonaio/runner/pkg/docker"
	"github.com/daytonaio/runner/pkg/runner"
	"github.com/gin-gonic/gin"
)

const (
	terminalXAssignmentBootstrapMediaType          = "application/vnd.terminalx.assignment-bootstrap.v1"
	terminalXAssignmentBootstrapInstalledMediaType = "application/vnd.terminalx.assignment-bootstrap-installed.v1+json"
	terminalXAssignmentBootstrapRequestBytes       = int64(3 * 1024 * 1024)
)

// TerminalXAssignmentBootstrap invokes one digest-pinned, root-owned
// provisioner with a bounded opaque envelope. No path, argument, uid,
// environment, working directory, privilege, or TTY setting is caller supplied.
func TerminalXAssignmentBootstrap(ctx *gin.Context) {
	if !validTerminalXSandboxID(ctx.Param("sandboxId")) ||
		len(ctx.Request.Header.Values("Content-Type")) != 1 ||
		len(ctx.Request.Header.Values("Accept")) != 1 ||
		!exactTerminalXMediaType(ctx.GetHeader("Content-Type"), terminalXAssignmentBootstrapMediaType) ||
		strings.TrimSpace(ctx.GetHeader("Accept")) != terminalXAssignmentBootstrapInstalledMediaType {
		ctx.Request.Close = true
		ctx.Header("Connection", "close")
		ctx.Status(http.StatusBadRequest)
		return
	}

	requestBytes, status := readTerminalXProtocolBody(ctx, terminalXAssignmentBootstrapRequestBytes)
	if status != 0 {
		ctx.Status(status)
		return
	}
	defer zeroTerminalXBytes(requestBytes)

	instance, err := runner.GetInstance(nil)
	if err != nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	responseBytes, err := instance.Docker.RunTerminalXAssignmentBootstrap(
		ctx.Request.Context(),
		ctx.Param("sandboxId"),
		requestBytes,
	)
	if err != nil {
		ctx.Status(terminalXAssignmentBootstrapStatus(err))
		return
	}
	defer zeroTerminalXBytes(responseBytes)

	ctx.Header("Cache-Control", "no-store")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Data(http.StatusOK, terminalXAssignmentBootstrapInstalledMediaType, responseBytes)
}

func terminalXAssignmentBootstrapStatus(err error) int {
	switch {
	case errors.Is(err, terminalxdocker.ErrTerminalXAssignmentBootstrapInvalid):
		return http.StatusBadRequest
	case errors.Is(err, terminalxdocker.ErrTerminalXAssignmentBootstrapConflict):
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}
