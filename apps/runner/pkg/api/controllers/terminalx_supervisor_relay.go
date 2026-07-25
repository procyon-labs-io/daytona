// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"io"
	"net/http"
	"strings"

	"github.com/daytonaio/runner/pkg/runner"
	"github.com/gin-gonic/gin"
)

const terminalXSupervisorMediaType = "application/vnd.terminalx.supervisor-framed"
const terminalXSupervisorMaximumRequestBytes int64 = 1024*1024 + 4

// TerminalXSupervisorRelay is deliberately not a general Docker exec API. It
// accepts one bounded framed-protocol input and invokes the single digest-pinned
// root relay selected by the hardened runner. Authentication is consumed by the
// runner middleware before any byte can enter the Sandbox.
func TerminalXSupervisorRelay(ctx *gin.Context) {
	if !validTerminalXSandboxID(ctx.Param("sandboxId")) ||
		len(ctx.Request.Header.Values("Content-Type")) != 1 ||
		len(ctx.Request.Header.Values("Accept")) != 1 ||
		!exactTerminalXMediaType(ctx.GetHeader("Content-Type"), terminalXSupervisorMediaType) ||
		strings.TrimSpace(ctx.GetHeader("Accept")) != terminalXSupervisorMediaType {
		ctx.Request.Close = true
		ctx.Header("Connection", "close")
		ctx.Status(http.StatusBadRequest)
		return
	}
	requestBytes, status := readTerminalXProtocolBody(ctx, terminalXSupervisorMaximumRequestBytes)
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
	stream, err := instance.Docker.OpenTerminalXSupervisorRelay(
		ctx.Request.Context(),
		ctx.Param("sandboxId"),
		requestBytes,
	)
	if err != nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	defer stream.Close()

	ctx.Header("Content-Type", terminalXSupervisorMediaType)
	ctx.Header("Cache-Control", "no-store")
	ctx.Header("X-Content-Type-Options", "nosniff")
	ctx.Status(http.StatusOK)
	if _, err := io.Copy(ctx.Writer, stream); err != nil && !ctx.Writer.Written() {
		ctx.Error(err)
	}
}
