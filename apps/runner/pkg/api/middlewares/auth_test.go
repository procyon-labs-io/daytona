// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package middlewares

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daytonaio/runner/internal/constants"
	"github.com/gin-gonic/gin"
	sloggin "github.com/samber/slog-gin"
)

func TestAuthMiddlewareConsumesEveryAuthorizationHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		daytonaAuth string
		auth        string
	}{
		{name: "daytona header", daytonaAuth: "Bearer runner-secret", auth: "Bearer shadow-secret"},
		{name: "standard header", auth: "Bearer runner-secret"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recorder := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(recorder)
			request := httptest.NewRequest(http.MethodGet, "/sandboxes/id/toolbox/version", nil)
			request.Header.Set(constants.DAYTONA_AUTHORIZATION_HEADER, test.daytonaAuth)
			request.Header.Set(constants.AUTHORIZATION_HEADER, test.auth)
			ctx.Request = request
			handler := AuthMiddleware("runner-secret")
			handler(ctx)
			if ctx.IsAborted() {
				t.Fatal("valid runner credential was rejected")
			}
			if got := request.Header.Get(constants.DAYTONA_AUTHORIZATION_HEADER); got != "" {
				t.Fatalf("Daytona authorization leaked: %q", got)
			}
			if got := request.Header.Get(constants.AUTHORIZATION_HEADER); got != "" {
				t.Fatalf("Authorization leaked: %q", got)
			}
		})
	}
}

func TestStartAuthTokenNeverAppearsInAccessLogs(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	router := gin.New()
	router.Use(RedactStartTokenQuery())
	router.Use(sloggin.New(logger))
	var recoveredToken string
	router.POST("/sandboxes/:id/start", func(ctx *gin.Context) {
		recoveredToken = StartToken(ctx)
		ctx.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodPost,
		"/sandboxes/sandbox-1/start?token=daemon-super-secret&safe=value", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status = %d", recorder.Code)
	}
	if recoveredToken != "daemon-super-secret" {
		t.Fatalf("controller token = %q", recoveredToken)
	}
	if strings.Contains(logs.String(), "daemon-super-secret") || strings.Contains(logs.String(), "token=") {
		t.Fatalf("sensitive start token reached request logs: %s", logs.String())
	}
	if !strings.Contains(logs.String(), "safe=value") {
		t.Fatalf("non-sensitive query evidence missing: %s", logs.String())
	}
}
