// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	cmap "github.com/orcaman/concurrent-map/v2"
)

func TestPTYConnectedControlFramePrecedesAlreadyQueuedOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var session *PTYSession
	handler := &broadcastOnAttachHandler{onAttach: func() {
		// This runs synchronously after registration. It models a shell prompt
		// arriving in the narrow registration/control-frame window.
		session.broadcast([]byte("immediate prompt"))
	}}
	session = &PTYSession{
		logger:  slog.New(handler),
		info:    PTYSessionInfo{ID: "test", Active: true},
		ctx:     ctx,
		clients: cmap.New[*wsClient](),
	}

	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		session.attachWebSocket(conn)
	}))
	t.Cleanup(server.Close)

	url := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))

	messageType, first, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read connected frame: %v", err)
	}
	var control struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	if messageType != websocket.TextMessage || json.Unmarshal(first, &control) != nil ||
		control.Type != "control" || control.Status != "connected" {
		t.Fatalf("first frame type=%d payload=%q, want connected control", messageType, first)
	}

	messageType, second, err := client.ReadMessage()
	if err != nil {
		t.Fatalf("read queued output: %v", err)
	}
	if messageType != websocket.BinaryMessage || string(second) != "immediate prompt" {
		t.Fatalf("second frame type=%d payload=%q", messageType, second)
	}
}

func TestPTYAttachAfterKillSweepIsRejected(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := &PTYSession{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		info:    PTYSessionInfo{ID: "connect-delete-race", Active: true},
		ctx:     ctx,
		cancel:  cancel,
		clients: cmap.New[*wsClient](),
	}

	upgraded := make(chan struct{})
	releaseAttach := make(chan struct{})
	handlerDone := make(chan struct{})
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		close(upgraded)
		<-releaseAttach
		session.attachWebSocket(conn)
		close(handlerDone)
	}))
	t.Cleanup(server.Close)

	type dialResult struct {
		conn *websocket.Conn
		err  error
	}
	dialed := make(chan dialResult, 1)
	go func() {
		url := "ws" + strings.TrimPrefix(server.URL, "http")
		conn, _, err := websocket.DefaultDialer.Dial(url, nil)
		dialed <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-upgraded:
	case <-time.After(2 * time.Second):
		t.Fatal("websocket was not upgraded")
	}
	result := <-dialed
	if result.err != nil {
		t.Fatalf("dial websocket: %v", result.err)
	}
	t.Cleanup(func() { _ = result.conn.Close() })

	// Complete the client sweep before allowing the already-upgraded handler to
	// register. Before the lifecycle fence this client received "connected" and
	// survived the sweep as an orphan attachment.
	session.kill()
	close(releaseAttach)
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("attach did not terminate after teardown")
	}

	_ = result.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	messageType, payload, err := result.conn.ReadMessage()
	if err == nil {
		t.Fatalf("received frame after completed kill: type=%d payload=%q", messageType, payload)
	}
	if count := session.clients.Count(); count != 0 {
		t.Fatalf("session retained %d client(s) after kill", count)
	}
}

type broadcastOnAttachHandler struct {
	once     sync.Once
	onAttach func()
}

func (h *broadcastOnAttachHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *broadcastOnAttachHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message == "Client attached to PTY session" {
		h.once.Do(h.onAttach)
	}
	return nil
}

func (h *broadcastOnAttachHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *broadcastOnAttachHandler) WithGroup(string) slog.Handler { return h }
