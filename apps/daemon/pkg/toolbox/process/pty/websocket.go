// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

// attachWebSocket connects a new WebSocket client to the PTY session
func (s *PTYSession) attachWebSocket(ws *websocket.Conn) {
	cl := &wsClient{
		id:   uuid.NewString(),
		conn: ws,
		send: make(chan []byte, 256), // if full, drop slow client
		done: make(chan struct{}),
	}

	// Register under the same lifecycle lock used to mark teardown. Therefore
	// registration either happens before closing (and the teardown sweep must
	// observe it), or is rejected after closing; it can never appear after the
	// sweep has completed.
	ctx, sessionID, count, registered := s.registerClient(cl)
	if !registered {
		cl.close()
		return
	}
	s.logger.Debug("Client attached to PTY session", "clientId", cl.id, "sessionId", sessionID, "clientCount", count)

	// The connected control frame is the protocol fence: the supervisor ignores
	// binary frames before it. Keep the client registered so concurrent PTY
	// output is queued, but do not start the queue-draining writer until this
	// synchronous frame succeeds. That makes connected unconditionally first.
	successMsg := map[string]interface{}{
		"type":   "control",
		"status": "connected",
	}
	successJSON, err := json.Marshal(successMsg)
	if err != nil || cl.writeMessage(websocket.TextMessage, successJSON) != nil {
		s.clients.Remove(cl.id)
		cl.close()
		return
	}

	// Start PTY data flow - writer (PTY -> this client) only after the fence.
	go s.clientWriter(ctx, cl)

	// reader (this client -> PTY); blocks until disconnect
	s.clientReader(cl)

	// on exit, unregister
	s.clients.Remove(cl.id)

	cl.close()

	remaining := s.clients.Count()
	s.logger.Debug("Client detached from PTY session", "clientId", cl.id, "sessionId", sessionID, "clientCount", remaining)
}

func (s *PTYSession) registerClient(cl *wsClient) (context.Context, string, int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || !s.info.Active || s.ctx == nil {
		return nil, s.info.ID, s.clients.Count(), false
	}
	s.clients.Set(cl.id, cl)
	return s.ctx, s.info.ID, s.clients.Count(), true
}

// clientWriter sends PTY output to a specific WebSocket client
func (s *PTYSession) clientWriter(ctx context.Context, cl *wsClient) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-cl.done:
			return
		case b := <-cl.send:
			cl.writeMu.Lock()
			_ = cl.conn.SetWriteDeadline(time.Now().Add(writeWait))
			err := cl.conn.WriteMessage(websocket.BinaryMessage, b)
			cl.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// clientReader reads input from a WebSocket client and sends to PTY
func (s *PTYSession) clientReader(cl *wsClient) {
	conn := cl.conn
	conn.SetReadLimit(readLimit)

	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				s.logger.Debug("ws read error", "error", err)
			}
			return
		}
		// Send all message data to PTY (text or binary)
		if err := s.sendToPTY(data); err != nil {
			// Send error to client and close connection
			_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(
				websocket.CloseInternalServerErr, "PTY session unavailable",
			))
			return
		}
	}
}

// broadcast sends data to all connected WebSocket clients
func (s *PTYSession) broadcast(b []byte) {
	// send to each client; drop slow clients to avoid stalling the PTY
	s.clientsMu.RLock()
	for id, cl := range s.clients.Items() {
		select {
		case cl.send <- b:
		case <-cl.done:
			// client is shutting down, skip
		default:
			// client's outbound queue is full -> drop the client
			go func(id string, cl *wsClient) {
				_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(
					websocket.ClosePolicyViolation, "slow consumer",
				))
				cl.close()
			}(id, cl)
		}
	}
	s.clientsMu.RUnlock()
}

// closeClientsWithExitCode closes all WebSocket connections with structured exit data
func (s *PTYSession) closeClientsWithExitCode(exitCode int, exitReason string) {
	var wsCloseCode int
	var exitReasonStr *string

	// Map PTY exit codes to WebSocket close codes
	if exitCode == 0 {
		wsCloseCode = websocket.CloseNormalClosure
		exitReasonStr = nil // undefined for clean exit
	} else {
		wsCloseCode = websocket.CloseInternalServerErr
		// Set human-readable reason for non-zero exits
		switch {
		case exitCode == 130:
			reason := "Ctrl+C"
			exitReasonStr = &reason
		case exitCode == 137:
			reason := "SIGKILL"
			exitReasonStr = &reason
		case exitCode == 143:
			reason := "SIGTERM"
			exitReasonStr = &reason
		case exitCode > 128:
			sigNum := exitCode - 128
			reason := fmt.Sprintf("signal %d", sigNum)
			exitReasonStr = &reason
		default:
			reason := "non-zero exit"
			exitReasonStr = &reason
		}
	}

	// Create structured close data as JSON
	type CloseData struct {
		ExitCode   int     `json:"exitCode"`
		ExitReason *string `json:"exitReason,omitempty"`
	}

	closeData := CloseData{
		ExitCode:   exitCode,
		ExitReason: exitReasonStr,
	}

	closeJSON, _ := json.Marshal(closeData)

	s.clientsMu.Lock()
	for id, cl := range s.clients.Items() {
		_ = cl.writeMessage(websocket.CloseMessage, websocket.FormatCloseMessage(
			wsCloseCode, string(closeJSON),
		))
		cl.close()
		s.clients.Remove(id)
	}
	s.clientsMu.Unlock()
}
