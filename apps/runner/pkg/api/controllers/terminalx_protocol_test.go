// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package controllers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestTerminalXProtocolAcceptsOnlyExactUUIDv4SandboxIdentity(t *testing.T) {
	t.Parallel()
	if !validTerminalXSandboxID("123e4567-e89b-42d3-a456-426614174000") {
		t.Fatal("valid lowercase UUIDv4 rejected")
	}
	for _, value := range []string{
		"sandbox-1",
		"123e4567-e89b-12d3-a456-426614174000",
		"123E4567-E89B-42D3-A456-426614174000",
		"123e4567-e89b-42d3-a456-426614174000/../other",
		"123e4567-e89b-42d3-a456-42661417400",
	} {
		if validTerminalXSandboxID(value) {
			t.Fatalf("unsafe sandbox identity accepted: %q", value)
		}
	}
}

func TestTerminalXProtocolRejectsParameterizedOrMalformedMediaTypes(t *testing.T) {
	t.Parallel()
	const expected = "application/vnd.terminalx.assignment-bootstrap.v1"
	if !exactTerminalXMediaType(expected, expected) {
		t.Fatal("exact media type rejected")
	}
	for _, value := range []string{
		"",
		"application/octet-stream",
		expected + "; charset=utf-8",
		expected + "; malformed",
		expected + ", application/json",
	} {
		if exactTerminalXMediaType(value, expected) {
			t.Fatalf("non-exact media type accepted: %q", value)
		}
	}
}

func TestReadTerminalXProtocolBodyRequiresExactExplicitLengthAndClearsDeadline(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := map[string]struct {
		body             string
		contentLength    int64
		transferEncoding []string
		rawTransfer      string
		wantStatus       int
		wantBody         string
		wantDeadlines    int
	}{
		"exact body": {
			body:          "abc",
			contentLength: 3,
			wantBody:      "abc",
			wantDeadlines: 2,
		},
		"empty body": {
			contentLength: 0,
			wantStatus:    http.StatusBadRequest,
		},
		"unknown length": {
			body:          "abc",
			contentLength: -1,
			wantStatus:    http.StatusBadRequest,
		},
		"declared overflow": {
			body:          "abc",
			contentLength: 4,
			wantStatus:    http.StatusBadRequest,
		},
		"short body": {
			body:          "ab",
			contentLength: 3,
			wantStatus:    http.StatusBadRequest,
			wantDeadlines: 2,
		},
		"body longer than declaration": {
			body:          "abc",
			contentLength: 2,
			wantStatus:    http.StatusBadRequest,
			wantDeadlines: 2,
		},
		"parsed transfer encoding": {
			body:             "abc",
			contentLength:    -1,
			transferEncoding: []string{"chunked"},
			wantStatus:       http.StatusBadRequest,
		},
		"raw transfer encoding": {
			body:          "abc",
			contentLength: 3,
			rawTransfer:   "chunked",
			wantStatus:    http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			writer := &terminalXReadDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
			ctx, _ := gin.CreateTestContext(writer)
			request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.body))
			request.ContentLength = test.contentLength
			request.TransferEncoding = test.transferEncoding
			if test.rawTransfer != "" {
				request.Header.Set("Transfer-Encoding", test.rawTransfer)
			}
			ctx.Request = request

			body, status := readTerminalXProtocolBody(ctx, 3)
			defer zeroTerminalXBytes(body)
			if status != test.wantStatus || string(body) != test.wantBody {
				t.Fatalf("read body = status %d body %q, want status %d body %q", status, body, test.wantStatus, test.wantBody)
			}
			if request.Close != (test.wantStatus != 0) {
				t.Fatalf("request close = %t for status %d", request.Close, test.wantStatus)
			}
			wantConnection := ""
			if test.wantStatus != 0 {
				wantConnection = "close"
			}
			if got := ctx.Writer.Header().Get("Connection"); got != wantConnection {
				t.Fatalf("Connection header = %q, want %q", got, wantConnection)
			}
			if len(writer.deadlines) != test.wantDeadlines {
				t.Fatalf("deadline calls = %d, want %d", len(writer.deadlines), test.wantDeadlines)
			}
			if test.wantDeadlines == 2 {
				if writer.deadlines[0].IsZero() || !writer.deadlines[1].IsZero() {
					t.Fatalf("read deadline was not installed then cleared: %v", writer.deadlines)
				}
				duration := writer.deadlines[0].Sub(writer.deadlineCalls[0])
				if duration < 9*time.Second || duration > 11*time.Second {
					t.Fatalf("read deadline duration = %v", duration)
				}
			}
		})
	}
}

func TestReadTerminalXProtocolBodyMapsDeadlineAndReadFailuresToUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := map[string]struct {
		writer     http.ResponseWriter
		body       io.Reader
		wantCalls  int
		wantStatus int
	}{
		"unsupported deadline": {
			writer:     httptest.NewRecorder(),
			body:       strings.NewReader("x"),
			wantStatus: http.StatusServiceUnavailable,
		},
		"deadline install failure": {
			writer: &terminalXReadDeadlineRecorder{
				ResponseRecorder: httptest.NewRecorder(),
				failCall:         1,
			},
			body:       strings.NewReader("x"),
			wantCalls:  1,
			wantStatus: http.StatusServiceUnavailable,
		},
		"deadline reset failure": {
			writer: &terminalXReadDeadlineRecorder{
				ResponseRecorder: httptest.NewRecorder(),
				failCall:         2,
			},
			body:       strings.NewReader("x"),
			wantCalls:  2,
			wantStatus: http.StatusServiceUnavailable,
		},
		"body read failure": {
			writer:     &terminalXReadDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()},
			body:       terminalXFailingReader{failure: errors.New("request body read failed")},
			wantCalls:  2,
			wantStatus: http.StatusServiceUnavailable,
		},
		"unexpected end of declared body": {
			writer:     &terminalXReadDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()},
			body:       terminalXFailingReader{failure: io.ErrUnexpectedEOF},
			wantCalls:  2,
			wantStatus: http.StatusBadRequest,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			ctx, _ := gin.CreateTestContext(test.writer)
			request := httptest.NewRequest(http.MethodPost, "/", test.body)
			request.ContentLength = 1
			ctx.Request = request

			body, status := readTerminalXProtocolBody(ctx, 1)
			if body != nil || status != test.wantStatus {
				t.Fatalf("read failure = status %d body %q", status, body)
			}
			if !request.Close {
				t.Fatal("failed request was left reusable with an unread or indeterminate body")
			}
			if got := ctx.Writer.Header().Get("Connection"); got != "close" {
				t.Fatalf("Connection header = %q", got)
			}
			if writer, ok := test.writer.(*terminalXReadDeadlineRecorder); ok && len(writer.deadlines) != test.wantCalls {
				t.Fatalf("deadline calls = %d, want %d", len(writer.deadlines), test.wantCalls)
			}
		})
	}
}

func TestTerminalXRoutesFailClosedWhenReadDeadlineIsUnsupported(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := map[string]struct {
		path        string
		contentType string
		accept      string
		handler     gin.HandlerFunc
	}{
		"assignment bootstrap": {
			path:        "/sandboxes/123e4567-e89b-42d3-a456-426614174000/terminalx-assignment-bootstrap",
			contentType: terminalXAssignmentBootstrapMediaType,
			accept:      terminalXAssignmentBootstrapInstalledMediaType,
			handler:     TerminalXAssignmentBootstrap,
		},
		"supervisor relay": {
			path:        "/sandboxes/123e4567-e89b-42d3-a456-426614174000/terminalx-supervisor-relay",
			contentType: terminalXSupervisorMediaType,
			accept:      terminalXSupervisorMediaType,
			handler:     TerminalXSupervisorRelay,
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			request := httptest.NewRequest(http.MethodPost, test.path, strings.NewReader("x"))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Accept", test.accept)
			ctx.Request = request
			ctx.Params = gin.Params{{Key: "sandboxId", Value: "123e4567-e89b-42d3-a456-426614174000"}}

			test.handler(ctx)
			if ctx.Writer.Status() != http.StatusServiceUnavailable || response.Body.Len() != 0 {
				t.Fatalf("unsupported deadline response = %d %q", ctx.Writer.Status(), response.Body.String())
			}
			if !request.Close {
				t.Fatal("unsupported deadline left request connection reusable")
			}
			if got := response.Header().Get("Connection"); got != "close" {
				t.Fatalf("Connection header = %q", got)
			}
		})
	}
}

type terminalXReadDeadlineRecorder struct {
	*httptest.ResponseRecorder
	deadlines     []time.Time
	deadlineCalls []time.Time
	failCall      int
}

func (writer *terminalXReadDeadlineRecorder) SetReadDeadline(deadline time.Time) error {
	writer.deadlines = append(writer.deadlines, deadline)
	writer.deadlineCalls = append(writer.deadlineCalls, time.Now())
	if writer.failCall == len(writer.deadlines) {
		return errors.New("read deadline unavailable")
	}
	return nil
}

type terminalXFailingReader struct {
	failure error
}

func (reader terminalXFailingReader) Read([]byte) (int, error) {
	return 0, reader.failure
}
