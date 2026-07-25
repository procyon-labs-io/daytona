// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	terminalxdocker "github.com/daytonaio/runner/pkg/docker"
	"github.com/gin-gonic/gin"
)

func TestTerminalXAssignmentBootstrapRejectsInvalidWireContractBeforeDispatch(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := map[string]struct {
		sandboxID   string
		contentType string
		accept      string
		body        string
		length      int64
		transfer    []string
	}{
		"invalid sandbox id": {
			sandboxID:   "sandbox-1",
			contentType: terminalXAssignmentBootstrapMediaType,
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
			body:        "x",
			length:      1,
		},
		"missing content type": {accept: terminalXAssignmentBootstrapInstalledMediaType, body: "x", length: 1},
		"wrong content type": {
			contentType: "application/octet-stream",
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
			body:        "x",
			length:      1,
		},
		"missing accept": {contentType: terminalXAssignmentBootstrapMediaType, body: "x", length: 1},
		"empty envelope": {
			contentType: terminalXAssignmentBootstrapMediaType,
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
		},
		"declared overflow": {
			contentType: terminalXAssignmentBootstrapMediaType,
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
			body:        "x",
			length:      terminalXAssignmentBootstrapRequestBytes + 1,
		},
		"chunked envelope": {
			contentType: terminalXAssignmentBootstrapMediaType,
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
			body:        "x",
			length:      -1,
			transfer:    []string{"chunked"},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			sandboxID := test.sandboxID
			if sandboxID == "" {
				sandboxID = "123e4567-e89b-42d3-a456-426614174000"
			}
			request := httptest.NewRequest(http.MethodPost, "/sandboxes/"+sandboxID+"/terminalx-assignment-bootstrap", strings.NewReader(test.body))
			request.ContentLength = test.length
			request.TransferEncoding = test.transfer
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			if test.accept != "" {
				request.Header.Set("Accept", test.accept)
			}
			ctx.Request = request
			ctx.Params = gin.Params{{Key: "sandboxId", Value: sandboxID}}

			TerminalXAssignmentBootstrap(ctx)
			if ctx.Writer.Status() != http.StatusBadRequest || response.Body.Len() != 0 {
				t.Fatalf("invalid contract response = %d %q", ctx.Writer.Status(), response.Body.String())
			}
		})
	}
}

func TestTerminalXAssignmentBootstrapStatusDoesNotExposeInternalFailures(t *testing.T) {
	t.Parallel()
	if status := terminalXAssignmentBootstrapStatus(fmt.Errorf("wrapped: %w", terminalxdocker.ErrTerminalXAssignmentBootstrapInvalid)); status != http.StatusBadRequest {
		t.Fatalf("invalid status = %d", status)
	}
	if status := terminalXAssignmentBootstrapStatus(fmt.Errorf("wrapped: %w", terminalxdocker.ErrTerminalXAssignmentBootstrapConflict)); status != http.StatusConflict {
		t.Fatalf("conflict status = %d", status)
	}
	if status := terminalXAssignmentBootstrapStatus(fmt.Errorf("secret-bearing internal detail")); status != http.StatusServiceUnavailable {
		t.Fatalf("internal status = %d", status)
	}
}
