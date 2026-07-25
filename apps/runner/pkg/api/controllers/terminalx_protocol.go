// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
)

var terminalXSandboxID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

const terminalXProtocolBodyReadTimeout = 10 * time.Second

func validTerminalXSandboxID(value string) bool {
	return terminalXSandboxID.MatchString(value)
}

func exactTerminalXMediaType(value string, expected string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == expected && len(parameters) == 0
}

// readTerminalXProtocolBody accepts only a complete, explicitly sized body.
// The route-local read deadline is cleared before returning so it can never
// truncate a long-lived supervisor response or poison a reused connection.
func readTerminalXProtocolBody(ctx *gin.Context, maximumBytes int64) ([]byte, int) {
	request := ctx.Request
	fail := func(status int) ([]byte, int) {
		if request != nil {
			request.Close = true
		}
		ctx.Header("Connection", "close")
		return nil, status
	}
	if request == nil || request.Body == nil || maximumBytes < 1 ||
		request.ContentLength < 1 || request.ContentLength > maximumBytes ||
		len(request.TransferEncoding) != 0 || len(request.Header.Values("Transfer-Encoding")) != 0 {
		return fail(http.StatusBadRequest)
	}

	controller := http.NewResponseController(ctx.Writer)
	if err := controller.SetReadDeadline(time.Now().Add(terminalXProtocolBodyReadTimeout)); err != nil {
		return fail(http.StatusServiceUnavailable)
	}
	requestBytes, readErr := io.ReadAll(io.LimitReader(request.Body, request.ContentLength+1))
	resetErr := controller.SetReadDeadline(time.Time{})
	if resetErr != nil {
		zeroTerminalXBytes(requestBytes)
		return fail(http.StatusServiceUnavailable)
	}
	if readErr != nil {
		zeroTerminalXBytes(requestBytes)
		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return fail(http.StatusBadRequest)
		}
		return fail(http.StatusServiceUnavailable)
	}
	if int64(len(requestBytes)) != request.ContentLength || int64(len(requestBytes)) > maximumBytes {
		zeroTerminalXBytes(requestBytes)
		return fail(http.StatusBadRequest)
	}
	return requestBytes, 0
}

func zeroTerminalXBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
