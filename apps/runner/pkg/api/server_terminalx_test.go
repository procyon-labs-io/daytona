// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package api

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTerminalXHardenedServerHasExactRouteSet(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	server := NewApiServer(ApiServerConfig{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ApiToken:          "test-token-that-is-long-enough-for-this-route-test",
		TerminalXHardened: true,
	})
	router := server.buildRouter(context.Background(), "development")

	want := map[string]bool{
		"GET /":                              true,
		"GET /info":                          true,
		"GET /metrics":                       true,
		"POST /sandboxes":                    true,
		"GET /sandboxes/:sandboxId":          true,
		"POST /sandboxes/:sandboxId/destroy": true,
		"POST /sandboxes/:sandboxId/start":   true,
		"POST /sandboxes/:sandboxId/stop":    true,
		"POST /sandboxes/:sandboxId/terminalx-assignment-bootstrap": true,
		"POST /sandboxes/:sandboxId/terminalx-supervisor-relay":     true,
	}
	routes := router.Routes()
	if len(routes) != len(want) {
		t.Fatalf("hardened route count = %d, want %d: %#v", len(routes), len(want), routes)
	}
	for _, route := range routes {
		key := route.Method + " " + route.Path
		if !want[key] {
			t.Fatalf("hardened runner exposed unexpected route %q", key)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("hardened runner omitted required routes: %#v", want)
	}
}

func TestTerminalXHardenedServerOmitsLegacySandboxEffectsAndToolboxProxy(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	hardened := gin.New()
	registerLegacySandboxRoutes(hardened.Group("/sandboxes"), logger, true)
	if routes := hardened.Routes(); len(routes) != 0 {
		t.Fatalf("hardened runner exposed generic toolbox routes: %#v", routes)
	}

	ordinary := gin.New()
	registerLegacySandboxRoutes(ordinary.Group("/sandboxes"), logger, false)
	routes := ordinary.Routes()
	if len(routes) == 0 {
		t.Fatal("ordinary Daytona runner lost its toolbox compatibility routes")
	}
	wantPaths := map[string]bool{
		"/sandboxes/:sandboxId/backup":                true,
		"/sandboxes/:sandboxId/snapshot-from-sandbox": true,
		"/sandboxes/:sandboxId/resize":                true,
		"/sandboxes/:sandboxId/recover":               true,
		"/sandboxes/:sandboxId/is-recoverable":        true,
		"/sandboxes/:sandboxId/network-settings":      true,
		"/sandboxes/:sandboxId/toolbox/*path":         true,
	}
	seenPaths := make(map[string]bool)
	for _, route := range routes {
		if !wantPaths[route.Path] {
			t.Fatalf("unexpected ordinary compatibility route: %#v", route)
		}
		seenPaths[route.Path] = true
	}
	for path := range wantPaths {
		if !seenPaths[path] {
			t.Fatalf("ordinary Daytona runner lost compatibility route %q", path)
		}
	}
}
