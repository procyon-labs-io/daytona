// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package pty

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestPTYManagerAtomicallyClaimsSessionIdentifier(t *testing.T) {
	manager := NewPTYManager()
	const contenders = 64

	start := make(chan struct{})
	var wg sync.WaitGroup
	var winners atomic.Int32
	winner := make(chan *PTYSession, 1)
	for range contenders {
		session := &PTYSession{info: PTYSessionInfo{ID: "shared"}}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if manager.Add(session) {
				winners.Add(1)
				winner <- session
			}
		}()
	}
	close(start)
	wg.Wait()
	close(winner)

	if got := winners.Load(); got != 1 {
		t.Fatalf("atomic Add winners = %d, want 1", got)
	}
	want := <-winner
	got, ok := manager.Get("shared")
	if !ok || got != want {
		t.Fatalf("manager owner = %p,%v want %p,true", got, ok, want)
	}
}

func TestPTYManagerDeleteExactFencesOldReaperFromReplacement(t *testing.T) {
	manager := NewPTYManager()
	oldSession := &PTYSession{info: PTYSessionInfo{ID: "reused"}}
	replacement := &PTYSession{info: PTYSessionInfo{ID: "reused"}}

	if !manager.Add(oldSession) || !manager.DeleteExact("reused", oldSession) || !manager.Add(replacement) {
		t.Fatal("failed to establish replacement session")
	}

	const staleReapers = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	var staleDeletes atomic.Int32
	for range staleReapers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if manager.DeleteExact("reused", oldSession) {
				staleDeletes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := staleDeletes.Load(); got != 0 {
		t.Fatalf("stale reapers removed replacement %d times", got)
	}
	got, ok := manager.Get("reused")
	if !ok || got != replacement {
		t.Fatalf("replacement owner = %p,%v want %p,true", got, ok, replacement)
	}
	if !manager.DeleteExact("reused", replacement) {
		t.Fatal("current owner could not remove itself")
	}
}

func TestPTYManagerVerificationUsesReceiver(t *testing.T) {
	original := ptyManager
	ptyManager = NewPTYManager()
	t.Cleanup(func() { ptyManager = original })

	globalSession := &PTYSession{info: PTYSessionInfo{ID: "global", Active: true}}
	if !ptyManager.Add(globalSession) {
		t.Fatal("failed to seed global manager")
	}

	local := NewPTYManager()
	if session, err := local.VerifyPTYSessionReady("global"); err == nil || session != nil {
		t.Fatalf("receiver-local lookup returned global session: session=%p err=%v", session, err)
	}
	if session, err := local.VerifyPTYSessionForResize("global"); err == nil || session != nil {
		t.Fatalf("receiver-local resize lookup returned global session: session=%p err=%v", session, err)
	}
}
