// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

// Package terminalxlog contains the fail-closed log boundary for the
// TerminalX hardened runner profile.
package terminalxlog

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

var (
	terminalXProviderIDPattern       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b`)
	terminalXContainerIDPattern      = regexp.MustCompile(`(?i)\b(?:sha256:)?[0-9a-f]{64}\b`)
	terminalXShortContainerIDPattern = regexp.MustCompile(`(?i)\b[0-9a-f]{12}\b`)
)

const (
	terminalXProviderIDReplacement  = "[terminalx-provider-id-redacted]"
	terminalXContainerIDReplacement = "[terminalx-container-id-redacted]"
	terminalXSecretReplacement      = "[terminalx-secret-redacted]"
)

// NewRedactingHandler wraps a slog handler so that provider UUIDs, Docker
// identifiers, and explicitly supplied process credentials cannot leave the
// hardened runner through ordinary structured logs. Any values are rendered
// through the same string scrubber because errors and nested structures can
// otherwise conceal identifiers from attribute-only redaction.
func NewRedactingHandler(next slog.Handler, secrets ...string) slog.Handler {
	filteredSecrets := make([]string, 0, len(secrets))
	for _, secret := range secrets {
		if secret != "" {
			filteredSecrets = append(filteredSecrets, secret)
		}
	}
	return &redactingHandler{next: next, secrets: filteredSecrets}
}

type redactingHandler struct {
	next    slog.Handler
	secrets []string
}

func (handler *redactingHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return handler.next.Enabled(ctx, level)
}

func (handler *redactingHandler) Handle(ctx context.Context, record slog.Record) error {
	redacted := slog.NewRecord(
		record.Time,
		record.Level,
		handler.redactString(record.Message),
		record.PC,
	)
	record.Attrs(func(attribute slog.Attr) bool {
		redacted.AddAttrs(handler.redactAttr(attribute))
		return true
	})
	return handler.next.Handle(ctx, redacted)
}

func (handler *redactingHandler) WithAttrs(attributes []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, 0, len(attributes))
	for _, attribute := range attributes {
		redacted = append(redacted, handler.redactAttr(attribute))
	}
	return &redactingHandler{
		next:    handler.next.WithAttrs(redacted),
		secrets: handler.secrets,
	}
}

func (handler *redactingHandler) WithGroup(name string) slog.Handler {
	return &redactingHandler{
		next:    handler.next.WithGroup(handler.redactString(name)),
		secrets: handler.secrets,
	}
}

func (handler *redactingHandler) redactAttr(attribute slog.Attr) slog.Attr {
	attribute.Key = handler.redactString(attribute.Key)
	attribute.Value = attribute.Value.Resolve()
	switch attribute.Value.Kind() {
	case slog.KindString:
		attribute.Value = slog.StringValue(handler.redactString(attribute.Value.String()))
	case slog.KindAny:
		attribute.Value = slog.StringValue(handler.redactString(fmt.Sprint(attribute.Value.Any())))
	case slog.KindGroup:
		group := attribute.Value.Group()
		redacted := make([]slog.Attr, 0, len(group))
		for _, child := range group {
			redacted = append(redacted, handler.redactAttr(child))
		}
		attribute.Value = slog.GroupValue(redacted...)
	}
	return attribute
}

func (handler *redactingHandler) redactString(value string) string {
	for _, secret := range handler.secrets {
		value = strings.ReplaceAll(value, secret, terminalXSecretReplacement)
	}
	value = terminalXProviderIDPattern.ReplaceAllString(value, terminalXProviderIDReplacement)
	value = terminalXContainerIDPattern.ReplaceAllString(value, terminalXContainerIDReplacement)
	return terminalXShortContainerIDPattern.ReplaceAllString(value, terminalXContainerIDReplacement)
}
