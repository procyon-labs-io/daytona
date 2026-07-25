// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package terminalxlog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestRedactingHandlerRemovesIdentifiersAndCredentialsRecursively(t *testing.T) {
	const (
		providerID  = "aa5e8e56-995b-4af8-95f0-fbff9b3ea329"
		containerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		secret      = "runner-token-that-must-never-be-logged"
	)

	var output bytes.Buffer
	handler := NewRedactingHandler(slog.NewJSONHandler(&output, nil), secret)
	logger := slog.New(handler).
		With("provider", providerID).
		WithGroup("assignment-" + providerID)

	nestedErr := fmt.Errorf(
		"sandbox %s container %s: %w",
		providerID,
		containerID,
		errors.New("credential "+secret+" short container 0123456789ab"),
	)
	logger.ErrorContext(context.Background(), "failed "+providerID, slog.Group(
		"nested",
		slog.Any("failure", nestedErr),
		slog.Any("values", map[string]any{
			"provider":  providerID,
			"container": "sha256:" + containerID,
			"secret":    secret,
		}),
	))

	got := output.String()
	for _, forbidden := range []string{providerID, containerID, containerID[:12], secret} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("redacted log contains %q: %s", forbidden, got)
		}
	}
	for _, replacement := range []string{
		terminalXProviderIDReplacement,
		terminalXContainerIDReplacement,
		terminalXSecretReplacement,
	} {
		if !strings.Contains(got, replacement) {
			t.Fatalf("redacted log does not contain marker %q: %s", replacement, got)
		}
	}
}

func TestRedactingHandlerPreservesOrdinaryStructuredValues(t *testing.T) {
	var output bytes.Buffer
	logger := slog.New(NewRedactingHandler(slog.NewJSONHandler(&output, nil)))
	logger.Info("runner ready", "attempt", 3, "healthy", true)

	got := output.String()
	for _, expected := range []string{`"msg":"runner ready"`, `"attempt":3`, `"healthy":true`} {
		if !strings.Contains(got, expected) {
			t.Fatalf("ordinary structured value %q missing from %s", expected, got)
		}
	}
}
