// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import "sync"

const (
	terminalXAssignmentBootstrapMaximumGlobal     = 8
	terminalXAssignmentBootstrapMaximumPerSandbox = 1
	terminalXSupervisorRelayMaximumGlobal         = 64
	terminalXSupervisorRelayMaximumPerSandbox     = 32
)

type terminalXOperationLimiter struct {
	mu        sync.Mutex
	global    int
	bySandbox map[string]int
}

func (limiter *terminalXOperationLimiter) acquire(
	canonicalSandboxID string,
	maximumPerSandbox int,
	maximumGlobal int,
) (func(), bool) {
	if canonicalSandboxID == "" || maximumPerSandbox < 1 || maximumGlobal < 1 {
		return nil, false
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.global >= maximumGlobal || limiter.bySandbox[canonicalSandboxID] >= maximumPerSandbox {
		return nil, false
	}
	if limiter.bySandbox == nil {
		limiter.bySandbox = make(map[string]int)
	}
	limiter.global++
	limiter.bySandbox[canonicalSandboxID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			limiter.mu.Lock()
			defer limiter.mu.Unlock()
			limiter.global--
			limiter.bySandbox[canonicalSandboxID]--
			if limiter.bySandbox[canonicalSandboxID] == 0 {
				delete(limiter.bySandbox, canonicalSandboxID)
			}
		})
	}, true
}
