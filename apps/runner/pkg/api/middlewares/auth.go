// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package middlewares

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"

	"github.com/daytonaio/runner/internal/constants"
	"github.com/gin-gonic/gin"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
)

const startTokenContextKey = "daytona.start-token"

// RedactStartTokenQuery removes the legacy sandbox daemon token from the URL
// before any request logger or telemetry middleware can observe RawQuery. The
// controller retrieves it from process-local Gin context for backwards
// compatibility; hardened runners reject/ignore this credential downstream.
func RedactStartTokenQuery() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		query := ctx.Request.URL.Query()
		if token := query.Get("token"); token != "" {
			ctx.Set(startTokenContextKey, token)
			query.Del("token")
			ctx.Request.URL.RawQuery = query.Encode()
		}
		ctx.Next()
	}
}

func StartToken(ctx *gin.Context) string {
	token, _ := ctx.Get(startTokenContextKey)
	value, _ := token.(string)
	return value
}

func AuthMiddleware(apiToken string) gin.HandlerFunc {
	expectedDigest := sha256.Sum256([]byte(apiToken))
	return func(ctx *gin.Context) {
		authHeader := ctx.GetHeader(constants.DAYTONA_AUTHORIZATION_HEADER)
		if authHeader == "" {
			authHeader = ctx.GetHeader(constants.AUTHORIZATION_HEADER)
		}

		ctx.Request.Header.Del(constants.DAYTONA_AUTHORIZATION_HEADER)
		// Neither the runner-wide credential nor a shadow Authorization value may
		// survive into toolbox reverse proxies. A sandbox-scoped daemon credential,
		// when introduced, must be injected from trusted runner state after this
		// middleware rather than accepted from the caller.
		ctx.Request.Header.Del(constants.AUTHORIZATION_HEADER)

		if authHeader == "" {
			ctx.Error(common_errors.NewUnauthorizedError(errors.New("authorization header required")))
			ctx.Abort()
			return
		}

		// Split "Bearer <token>"
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != constants.BEARER_AUTH_HEADER {
			ctx.Error(common_errors.NewUnauthorizedError(errors.New("invalid authorization header format")))
			ctx.Abort()
			return
		}

		token := parts[1]

		actualDigest := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(actualDigest[:], expectedDigest[:]) != 1 {
			ctx.Error(common_errors.NewUnauthorizedError(errors.New("invalid token")))
			ctx.Abort()
			return
		}

		// Authentication successful, continue to the next handler
		ctx.Next()
	}
}
