// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/daytonaio/runner/pkg/terminalxartifact"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("terminalx-artifact-manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runnerPath := flags.String("runner", "", "exact runner binary")
	daemonPath := flags.String("daemon", "", "exact daemon binary")
	expectedSourceCommit := flags.String("expected-source-commit", "", "exact clean source revision")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return fmt.Errorf("terminalx runtime artifact manifest arguments are invalid")
	}
	manifest, err := terminalxartifact.Generate(*runnerPath, *daemonPath, *expectedSourceCommit)
	if err != nil {
		return err
	}
	return writeManifest(output, manifest)
}

func writeManifest(output io.Writer, manifest []byte) error {
	payload := make([]byte, len(manifest)+1)
	copy(payload, manifest)
	payload[len(manifest)] = '\n'
	written, err := output.Write(payload)
	if err != nil || written != len(payload) {
		return fmt.Errorf("terminalx runtime artifact manifest could not be written")
	}
	return nil
}
