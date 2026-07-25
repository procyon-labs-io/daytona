// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

//	@title			Daytona Runner API
//	@version		v0.0.0-dev
//	@description	Daytona Runner API
//	@license.name	Apache-2.0
//	@license.url	https://www.apache.org/licenses/LICENSE-2.0

//	@securityDefinitions.apikey	Bearer
//	@in							header
//	@name						Authorization
//	@description				Type "Bearer" followed by a space and an API token.

//	@Security	Bearer

package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/daytonaio/runner/cmd/runner/config"
	"github.com/daytonaio/runner/internal"
	"github.com/daytonaio/runner/pkg/api/controllers"
	"github.com/daytonaio/runner/pkg/api/docs"
	"github.com/daytonaio/runner/pkg/api/middlewares"
	"github.com/daytonaio/runner/pkg/common"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"

	common_errors "github.com/daytonaio/common-go/pkg/errors"
	"github.com/daytonaio/common-go/pkg/log"
	common_proxy "github.com/daytonaio/common-go/pkg/proxy"
	sloggin "github.com/samber/slog-gin"

	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

type ApiServerConfig struct {
	Logger            *slog.Logger
	ApiPort           int
	ApiToken          string
	TLSCertFile       string
	TLSKeyFile        string
	EnableTLS         bool
	LogRequests       bool
	TerminalXHardened bool
}

func NewApiServer(config ApiServerConfig) *ApiServer {
	return &ApiServer{
		logger:            config.Logger.With(slog.String("component", "server")),
		apiPort:           config.ApiPort,
		apiToken:          config.ApiToken,
		tlsCertFile:       config.TLSCertFile,
		tlsKeyFile:        config.TLSKeyFile,
		enableTLS:         config.EnableTLS,
		logRequests:       config.LogRequests,
		terminalXHardened: config.TerminalXHardened,
	}
}

type ApiServer struct {
	logger            *slog.Logger
	apiPort           int
	apiToken          string
	tlsCertFile       string
	tlsKeyFile        string
	enableTLS         bool
	httpServer        *http.Server
	router            *gin.Engine
	logRequests       bool
	terminalXHardened bool
}

func (a *ApiServer) Start(ctx context.Context) error {
	docs.SwaggerInfo.Description = "Daytona Runner API"
	docs.SwaggerInfo.Title = "Daytona Runner API"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Version = internal.Version

	_, err := net.Dial("tcp", fmt.Sprintf(":%d", a.apiPort))
	if err == nil {
		return fmt.Errorf("cannot start API server, port %d is already in use", a.apiPort)
	}

	a.router = a.buildRouter(ctx, config.GetEnvironment())

	a.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", a.apiPort),
		Handler: a.router,
	}
	common_proxy.ApplyServerTimeouts(a.httpServer)

	listener, err := net.Listen("tcp", a.httpServer.Addr)
	if err != nil {
		return err
	}

	errChan := make(chan error)
	go func() {
		if a.enableTLS {
			// Start HTTPS server
			errChan <- a.httpServer.ServeTLS(listener, a.tlsCertFile, a.tlsKeyFile)
		} else {
			// Start HTTP server
			errChan <- a.httpServer.Serve(listener)
		}
	}()

	return <-errChan
}

func (a *ApiServer) buildRouter(ctx context.Context, environment string) *gin.Engine {
	binding.Validator = new(DefaultValidator)

	gin.DefaultWriter = &log.InfoLogWriter{}
	gin.DefaultErrorWriter = &log.ErrorLogWriter{}

	router := gin.New()
	router.Use(common_errors.Recovery())
	// This must precede request logging and telemetry: the legacy Start token is
	// sensitive even though hardened TerminalX sandboxes never consume it.
	router.Use(middlewares.RedactStartTokenQuery())

	gin.SetMode(gin.ReleaseMode)
	if environment == "development" && !a.terminalXHardened {
		gin.SetMode(gin.DebugMode)
	}

	if a.logRequests {
		router.Use(sloggin.New(a.logger))
	}
	if !a.terminalXHardened {
		router.Use(otelgin.Middleware("daytona-runner"))
	}
	router.Use(common_errors.NewErrorMiddleware(common.HandlePossibleDockerError))
	router.Use(middlewares.RecoverableErrorsMiddleware())

	public := router.Group("/")
	public.GET("", controllers.HealthCheck)

	if environment == "development" && !a.terminalXHardened {
		public.GET("/api/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	}

	protected := router.Group("/")
	protected.Use(middlewares.AuthMiddleware(a.apiToken))

	metricsController := protected.Group("/metrics")
	{
		metricsController.GET("", gin.WrapH(promhttp.Handler()))
	}

	infoController := protected.Group("/info")
	{
		infoController.GET("", controllers.RunnerInfo)
	}

	sandboxControllerLogger := a.logger.With(slog.String("component", "sandbox_controller"))
	sandboxController := protected.Group("/sandboxes")
	{
		sandboxController.POST("", controllers.Create)
		sandboxController.GET("/:sandboxId", controllers.Info)
		sandboxController.POST("/:sandboxId/destroy", controllers.Destroy)
		sandboxController.POST("/:sandboxId/start", controllers.Start)
		sandboxController.POST("/:sandboxId/stop", controllers.Stop)
		if a.terminalXHardened {
			sandboxController.POST("/:sandboxId/terminalx-assignment-bootstrap", controllers.TerminalXAssignmentBootstrap)
			sandboxController.POST("/:sandboxId/terminalx-supervisor-relay", controllers.TerminalXSupervisorRelay)
		}
		registerLegacySandboxRoutes(sandboxController, sandboxControllerLogger, a.terminalXHardened)
	}

	if !a.terminalXHardened {
		snapshotControllerLogger := a.logger.With(slog.String("component", "snapshot_controller"))
		snapshotController := protected.Group("/snapshots")
		{
			snapshotController.POST("/pull", controllers.PullSnapshot(ctx, snapshotControllerLogger))
			snapshotController.POST("/build", controllers.BuildSnapshot(ctx, snapshotControllerLogger))
			snapshotController.POST("/tag", controllers.TagImage)
			snapshotController.GET("/exists", controllers.SnapshotExists)
			snapshotController.GET("/info", controllers.GetSnapshotInfo)
			snapshotController.POST("/remove", controllers.RemoveSnapshot(snapshotControllerLogger))
			snapshotController.GET("/logs", controllers.GetBuildLogs(snapshotControllerLogger))
			snapshotController.POST("/inspect", controllers.InspectSnapshotInRegistry)
		}
	}

	return router
}

// registerLegacySandboxRoutes keeps compatibility effects reachable for
// ordinary Daytona runners. The hardened profile has its own narrow lifecycle
// and root protocol and must not expose mutation routes that it can never
// authorize. In particular, it deliberately leaves TCP/2280 unused; exposing
// the generic proxy would let uid 10001 bind that port and turn the runner into
// an unaudited HTTP/WebSocket bridge around the root supervisor and Team
// Session steering fences.
func registerLegacySandboxRoutes(
	sandboxController *gin.RouterGroup,
	logger *slog.Logger,
	terminalXHardened bool,
) {
	if terminalXHardened {
		return
	}
	sandboxController.POST("/:sandboxId/backup", controllers.CreateBackup(logger))
	sandboxController.POST("/:sandboxId/snapshot-from-sandbox", controllers.SnapshotFromSandbox)
	sandboxController.POST("/:sandboxId/resize", controllers.Resize)
	sandboxController.POST("/:sandboxId/recover", controllers.Recover)
	sandboxController.POST("/:sandboxId/is-recoverable", controllers.IsRecoverable)
	sandboxController.POST("/:sandboxId/network-settings", controllers.UpdateNetworkSettings)
	sandboxController.Any("/:sandboxId/toolbox/*path", controllers.ProxyRequest(logger))
}

func (a *ApiServer) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := a.httpServer.Shutdown(ctx); err != nil {
		a.logger.Error("Failed to shutdown API server", "error", err)
	}
}
