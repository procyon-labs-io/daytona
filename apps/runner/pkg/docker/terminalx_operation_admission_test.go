// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestTerminalXOperationLimiterUsesCanonicalSandboxAndExactCaps(t *testing.T) {
	t.Parallel()
	var limiter terminalXOperationLimiter
	releaseOne, ok := limiter.acquire("canonical-1", 1, 2)
	if !ok {
		t.Fatal("first operation rejected")
	}
	if _, ok := limiter.acquire("canonical-1", 1, 2); ok {
		t.Fatal("per-sandbox cap bypassed")
	}
	releaseTwo, ok := limiter.acquire("canonical-2", 1, 2)
	if !ok {
		t.Fatal("second sandbox rejected")
	}
	if _, ok := limiter.acquire("canonical-3", 1, 2); ok {
		t.Fatal("global cap bypassed")
	}
	releaseOne()
	releaseOne()
	if releaseThree, ok := limiter.acquire("canonical-3", 1, 2); !ok {
		t.Fatal("idempotent release did not free exactly one slot")
	} else {
		releaseThree()
	}
	releaseTwo()
}

func TestTerminalXOperationLimiterIsRaceSafe(t *testing.T) {
	t.Parallel()
	var limiter terminalXOperationLimiter
	var admitted atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 256; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			release, ok := limiter.acquire("sandbox", 8, 8)
			if !ok {
				return
			}
			admitted.Add(1)
			release()
			release()
		}(index)
	}
	wait.Wait()
	if admitted.Load() < 1 || limiter.global != 0 || len(limiter.bySandbox) != 0 {
		t.Fatalf("limiter did not return to zero: admitted=%d global=%d map=%v", admitted.Load(), limiter.global, limiter.bySandbox)
	}
}
