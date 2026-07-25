// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package toolbox

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestTerminalXInheritedListenerExposesOnlyRequiredPTYRoutes(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "daytona-daemon.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen Unix: %v", err)
	}
	server := NewServer(ServerConfig{
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		WorkDir:   "/home/terminalx",
		SandboxId: "terminalx-sandbox",
		Listener:  listener,
	})
	done := make(chan error, 1)
	go func() { done <- server.Start() }()
	t.Cleanup(func() {
		server.Shutdown()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("hardened toolbox server did not stop")
		}
	})

	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	t.Cleanup(transport.CloseIdleConnections)

	for path, wantStatus := range map[string]int{
		"/version":             http.StatusNotFound,
		"/process/pty":         http.StatusNotFound,
		"/process/pty/unknown": http.StatusNotFound,
		"/init":                http.StatusNotFound,
		"/files":               http.StatusNotFound,
		"/git/status":          http.StatusNotFound,
		"/lsp/start":           http.StatusNotFound,
		"/port":                http.StatusNotFound,
		"/proxy/80/":           http.StatusNotFound,
		"/swagger/x":           http.StatusNotFound,
		"/process/execute":     http.StatusNotFound,
		"/process/session":     http.StatusNotFound,
		"/process/interpreter": http.StatusNotFound,
		"/computeruse/status":  http.StatusNotFound,
	} {
		response, requestErr := client.Get("http://unix" + path)
		if requestErr != nil {
			t.Fatalf("GET %s: %v", path, requestErr)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != wantStatus {
			t.Fatalf("GET %s status=%d want=%d", path, response.StatusCode, wantStatus)
		}
	}
	if !server.hardened || server.httpServer == nil || server.httpServer.Addr != "" {
		t.Fatalf("hardened toolbox unexpectedly configured TCP: hardened=%v addr=%q", server.hardened, server.httpServer.Addr)
	}
	engine, ok := server.httpServer.Handler.(*gin.Engine)
	if !ok {
		t.Fatalf("hardened toolbox handler type = %T", server.httpServer.Handler)
	}
	routes := map[string]bool{}
	for _, route := range engine.Routes() {
		routes[route.Method+" "+route.Path] = true
	}
	wantRoutes := map[string]bool{
		"POST /process/pty":                   true,
		"DELETE /process/pty/:sessionId":      true,
		"GET /process/pty/:sessionId/connect": true,
		"POST /process/pty/:sessionId/resize": true,
	}
	if len(routes) != len(wantRoutes) {
		t.Fatalf("hardened toolbox routes = %#v", routes)
	}
	for route := range wantRoutes {
		if !routes[route] {
			t.Fatalf("hardened toolbox is missing exact route %q: %#v", route, routes)
		}
	}
}
