// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"slices"
	"testing"

	"github.com/docker/docker/api/types/container"
)

func TestTerminalXSupervisorExecOptionsHaveNoCallerControlledSurface(t *testing.T) {
	t.Parallel()
	options := terminalXSupervisorExecOptions()
	if options.User != "0:0" || options.Privileged || options.Tty || !options.AttachStdin ||
		!options.AttachStdout || !options.AttachStderr || options.WorkingDir != "/" ||
		len(options.Cmd) != 1 || options.Cmd[0] != terminalXSupervisorRelayPath ||
		len(options.Env) != 0 || options.Detach || options.DetachKeys != "" || options.ConsoleSize != nil {
		t.Fatalf("unsafe root relay exec options: %#v", options)
	}
}

func TestVerifyTerminalXSupervisorRelayArchivePinsRootRegularExecutable(t *testing.T) {
	t.Parallel()
	payload := []byte("terminalx-supervisor-relay-v1")
	digest := sha256.Sum256(payload)
	expected := hex.EncodeToString(digest[:])
	validArchive := func(headerMutator func(*tar.Header), extra bool) *bytes.Reader {
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		header := &tar.Header{
			Name:     "terminalx-supervisor-relay",
			Mode:     0o555,
			Uid:      0,
			Gid:      0,
			Size:     int64(len(payload)),
			Typeflag: tar.TypeReg,
		}
		if headerMutator != nil {
			headerMutator(header)
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if header.Typeflag == tar.TypeReg && header.Size > 0 {
			if _, err := writer.Write(payload[:header.Size]); err != nil {
				t.Fatalf("write payload: %v", err)
			}
		}
		if extra {
			if err := writer.WriteHeader(&tar.Header{Name: "extra", Mode: 0o444, Size: 1, Typeflag: tar.TypeReg}); err != nil {
				t.Fatalf("write extra header: %v", err)
			}
			if _, err := writer.Write([]byte("x")); err != nil {
				t.Fatalf("write extra payload: %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close tar: %v", err)
		}
		return bytes.NewReader(output.Bytes())
	}
	stat := container.PathStat{
		Name: "terminalx-supervisor-relay",
		Size: int64(len(payload)),
		Mode: 0o555,
	}
	if err := verifyTerminalXSupervisorRelayArchive(validArchive(nil, false), stat, expected); err != nil {
		t.Fatalf("valid relay rejected: %v", err)
	}

	tests := map[string]struct {
		mutateHeader func(*tar.Header)
		mutateStat   func(*container.PathStat)
		digest       string
		extra        bool
	}{
		"wrong digest":   {digest: testTerminalXSupervisorRelaySHA256},
		"non-root owner": {mutateHeader: func(value *tar.Header) { value.Uid = 1000 }},
		"writable executable": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o755 },
			mutateStat:   func(value *container.PathStat) { value.Mode = 0o755 },
		},
		"setuid executable": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o4555 },
			mutateStat:   func(value *container.PathStat) { value.Mode = os.ModeSetuid | 0o555 },
		},
		"symbolic link": {
			mutateHeader: func(value *tar.Header) {
				value.Typeflag = tar.TypeSymlink
				value.Size = 0
				value.Linkname = "other"
			},
		},
		"additional entry": {extra: true},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidateStat := stat
			if test.mutateStat != nil {
				test.mutateStat(&candidateStat)
			}
			candidateDigest := test.digest
			if candidateDigest == "" {
				candidateDigest = expected
			}
			if err := verifyTerminalXSupervisorRelayArchive(
				validArchive(test.mutateHeader, test.extra), candidateStat, candidateDigest,
			); err == nil {
				t.Fatal("unsafe relay artifact was accepted")
			}
		})
	}
}

func TestVerifyTerminalXRootDirectoryArchivePinsProtectedChain(t *testing.T) {
	t.Parallel()
	archive := func(headerMutator func(*tar.Header)) *bytes.Reader {
		var output bytes.Buffer
		writer := tar.NewWriter(&output)
		header := &tar.Header{
			Name:     "terminalx/",
			Mode:     0o755,
			Uid:      0,
			Gid:      0,
			Typeflag: tar.TypeDir,
		}
		if headerMutator != nil {
			headerMutator(header)
		}
		if err := writer.WriteHeader(header); err != nil {
			t.Fatalf("write directory header: %v", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("close directory tar: %v", err)
		}
		return bytes.NewReader(output.Bytes())
	}
	stat := container.PathStat{Name: "terminalx", Mode: os.ModeDir | 0o755}
	if err := verifyTerminalXRootDirectoryArchive(
		archive(nil), stat, "/usr/local/libexec/terminalx",
	); err != nil {
		t.Fatalf("valid protected directory rejected: %v", err)
	}
	tests := map[string]struct {
		mutateHeader func(*tar.Header)
		mutateStat   func(*container.PathStat)
	}{
		"non-root owner": {mutateHeader: func(value *tar.Header) { value.Uid = 1000 }},
		"writable parent": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o775 },
			mutateStat:   func(value *container.PathStat) { value.Mode = os.ModeDir | 0o775 },
		},
		"sticky parent": {
			mutateHeader: func(value *tar.Header) { value.Mode = 0o1755 },
			mutateStat:   func(value *container.PathStat) { value.Mode = os.ModeDir | os.ModeSticky | 0o755 },
		},
		"symlink parent": {
			mutateHeader: func(value *tar.Header) {
				value.Typeflag = tar.TypeSymlink
				value.Linkname = "other"
			},
			mutateStat: func(value *container.PathStat) {
				value.Mode = os.ModeSymlink | 0o755
				value.LinkTarget = "other"
			},
		},
		"nested archive name": {mutateHeader: func(value *tar.Header) { value.Name = "other/terminalx/" }},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			candidateStat := stat
			if test.mutateStat != nil {
				test.mutateStat(&candidateStat)
			}
			if err := verifyTerminalXRootDirectoryArchive(
				archive(test.mutateHeader), candidateStat, "/usr/local/libexec/terminalx",
			); err == nil {
				t.Fatal("unsafe protected directory was accepted")
			}
		})
	}
}

func TestTerminalXProtectedExecutableParentsIncludeEveryRenameBoundary(t *testing.T) {
	t.Parallel()
	if got, want := terminalXProtectedExecutableParents(terminalXSupervisorRelayPath), []string{
		"/",
		"/usr",
		"/usr/local",
		"/usr/local/libexec",
		"/usr/local/libexec/terminalx",
	}; !slices.Equal(got, want) {
		t.Fatalf("protected parent chain = %v, want %v", got, want)
	}
	if got, want := terminalXProtectedExecutableParents(terminalXNodePath), []string{
		"/",
		"/usr",
		"/usr/local",
		"/usr/local/bin",
	}; !slices.Equal(got, want) {
		t.Fatalf("node parent chain = %v, want %v", got, want)
	}
}
