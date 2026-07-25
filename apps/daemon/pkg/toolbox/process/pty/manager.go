// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"fmt"

	cmap "github.com/orcaman/concurrent-map/v2"
)

// Global PTY manager instance
var ptyManager = &PTYManager{
	sessions: cmap.New[*PTYSession](),
}

// NewPTYManager creates a new PTY manager instance
func NewPTYManager() *PTYManager {
	return &PTYManager{
		sessions: cmap.New[*PTYSession](),
	}
}

// Add atomically adds a PTY session to the manager. It returns false when the
// identifier is already owned by another session.
func (m *PTYManager) Add(s *PTYSession) bool {
	return m.sessions.SetIfAbsent(s.info.ID, s)
}

// Get retrieves a PTY session by ID
func (m *PTYManager) Get(id string) (*PTYSession, bool) {
	s, ok := m.sessions.Get(id)
	return s, ok
}

// Delete removes a PTY session from the manager
func (m *PTYManager) Delete(id string) (*PTYSession, bool) {
	return m.sessions.Pop(id)
}

// DeleteExact removes id only while it is still owned by expected. This
// prevents an old process reaper from deleting a newer session that reused the
// same identifier after explicit teardown.
func (m *PTYManager) DeleteExact(id string, expected *PTYSession) bool {
	return m.sessions.RemoveCb(id, func(_ string, current *PTYSession, exists bool) bool {
		return exists && current == expected
	})
}

// List returns information about all managed PTY sessions
func (m *PTYManager) List() []PTYSessionInfo {
	out := make([]PTYSessionInfo, 0, m.sessions.Count())
	for _, s := range m.sessions.Items() {
		out = append(out, s.Info())
	}
	return out
}

func (m *PTYManager) VerifyPTYSessionReady(id string) (*PTYSession, error) {
	// Validate session existence and send control message
	session, ok := m.Get(id)
	if !ok {
		return nil, fmt.Errorf("PTY session %s not found", id)
	}

	sessionInfo := session.Info()

	// Handle inactive sessions based on lazy start flag
	if !sessionInfo.Active {
		if sessionInfo.LazyStart {
			// Lazy start session - start PTY on first client connection
			if err := session.start(); err != nil {
				return nil, fmt.Errorf("failed to start PTY session: %v", err)
			}
		} else {
			// Non-lazy session that's inactive means it has terminated
			return nil, fmt.Errorf("PTY session '%s' has terminated and is no longer available", id)
		}
	}

	return session, nil
}

func (m *PTYManager) VerifyPTYSessionForResize(id string) (*PTYSession, error) {
	session, ok := m.Get(id)
	if !ok {
		return nil, fmt.Errorf("PTY session %s not found", id)
	}

	sessionInfo := session.Info()

	// Check if session can be resized
	if !sessionInfo.Active && !sessionInfo.LazyStart {
		// Non-lazy session that's inactive means it has terminated
		return nil, fmt.Errorf("PTY session '%s' has terminated and cannot be resized", id)
	}

	return session, nil
}
