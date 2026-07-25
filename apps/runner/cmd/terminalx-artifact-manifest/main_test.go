// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"bytes"
	"testing"
)

type terminalXShortWriter struct{}

func (terminalXShortWriter) Write(value []byte) (int, error) {
	if len(value) == 0 {
		return 0, nil
	}
	return len(value) - 1, nil
}

func TestWriteManifestRequiresCompleteCanonicalRecord(t *testing.T) {
	var output bytes.Buffer
	if err := writeManifest(&output, []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	if output.String() != "{\"version\":1}\n" {
		t.Fatalf("manifest framing changed: %q", output.String())
	}
	if err := writeManifest(terminalXShortWriter{}, []byte(`{"version":1}`)); err == nil {
		t.Fatal("partially written artifact manifest was accepted")
	}
}

func TestRunRejectsIncompleteArgumentsBeforeArtifactAccess(t *testing.T) {
	if err := run(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing artifact arguments were accepted")
	}
	if err := run([]string{"unexpected"}, &bytes.Buffer{}); err == nil {
		t.Fatal("positional artifact argument was accepted")
	}
}
