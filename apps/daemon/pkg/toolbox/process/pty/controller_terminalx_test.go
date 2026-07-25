// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTerminalXPTYControllerRequiresFixedSanitizedLazyRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := ptyManager
	t.Cleanup(func() { ptyManager = original })

	tests := map[string]string{
		"missing sanitizeEnv": `{"id":"6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"lazyStart":true}`,
		"false sanitizeEnv":   `{"id":"6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"lazyStart":true,"sanitizeEnv":false}`,
		"missing lazyStart":   `{"id":"6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"sanitizeEnv":true}`,
		"unsafe cwd":          `{"id":"6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51","cwd":"/tmp","envs":{"TERM":"xterm-256color"},"lazyStart":true,"sanitizeEnv":true}`,
		"unsafe env":          `{"id":"6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color","TOKEN":"private"},"lazyStart":true,"sanitizeEnv":true}`,
		"non-v4 UUID":         `{"id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"lazyStart":true,"sanitizeEnv":true}`,
		"noncanonical UUID":   `{"id":"6BA7B810-9DAD-4B4E-8A2B-8AEB9D2A4F51","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"lazyStart":true,"sanitizeEnv":true}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			ptyManager = NewPTYManager()
			response := issuePTYCreate(t, NewTerminalXPTYController(discardLogger(), terminalXPTYWorkingDirectory), body)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
			}
			if got := ptyManager.sessions.Count(); got != 0 {
				t.Fatalf("rejected request registered %d sessions", got)
			}
		})
	}
}

func TestTerminalXPTYControllerAcceptsExactSupervisorRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := ptyManager
	ptyManager = NewPTYManager()
	t.Cleanup(func() { ptyManager = original })

	const id = "6ba7b810-9dad-4b4e-8a2b-8aeb9d2a4f51"
	response := issuePTYCreate(t, NewTerminalXPTYController(discardLogger(), terminalXPTYWorkingDirectory),
		`{"id":"`+id+`","cwd":"/home/terminalx","envs":{"TERM":"xterm-256color"},"cols":80,"rows":24,"lazyStart":true,"sanitizeEnv":true}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	session, ok := ptyManager.Get(id)
	if !ok || !session.sanitizeEnv || !session.info.LazyStart {
		t.Fatalf("registered session = %#v,%v", session, ok)
	}
	ptyManager.DeleteExact(id, session)
}

func TestGeneralPTYControllerRetainsOrdinaryLazySessionBehavior(t *testing.T) {
	gin.SetMode(gin.TestMode)
	original := ptyManager
	ptyManager = NewPTYManager()
	t.Cleanup(func() { ptyManager = original })

	response := issuePTYCreate(t, NewPTYController(discardLogger(), "/workspace"),
		`{"id":"ordinary-id","cwd":"/tmp","envs":{"CUSTOM":"public"},"lazyStart":true}`)
	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", response.Code, response.Body.String())
	}
	session, ok := ptyManager.Get("ordinary-id")
	if !ok || session.sanitizeEnv || !session.info.LazyStart || session.info.Cwd != "/tmp" {
		t.Fatalf("ordinary session = %#v,%v", session, ok)
	}
	ptyManager.DeleteExact("ordinary-id", session)
}

func issuePTYCreate(t *testing.T, controller *PTYController, body string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/process/pty", controller.CreatePTYSession)
	request := httptest.NewRequest(http.MethodPost, "/process/pty", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
