// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package docker

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/containerd/errdefs"
	"github.com/daytonaio/runner/pkg/netrules"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
)

type dockerMonitorAPI interface {
	Events(ctx context.Context, options events.ListOptions) (<-chan events.Message, <-chan error)
	ContainerInspect(ctx context.Context, containerID string) (container.InspectResponse, error)
	ContainerList(ctx context.Context, options container.ListOptions) ([]container.Summary, error)
}

type MonitorOptions struct {
	OnDestroyEvent    func(ctx context.Context)
	TerminalXHardened bool
	TerminalXClient   *DockerClient
}

type DockerMonitor struct {
	apiClient           dockerMonitorAPI
	log                 *slog.Logger
	ctx                 context.Context
	cancel              context.CancelFunc
	netRulesManager     *netrules.NetRulesManager
	opts                MonitorOptions
	fatalErr            chan error
	terminalXEnforce    func(context.Context, *container.InspectResponse) error
	terminalXQuarantine func(context.Context, error) error
}

func NewDockerMonitor(logger *slog.Logger, apiClient dockerMonitorAPI, netRulesManager *netrules.NetRulesManager, opts MonitorOptions) *DockerMonitor {
	ctx, cancel := context.WithCancel(context.Background())
	monitor := &DockerMonitor{
		apiClient:       apiClient,
		log:             logger.With(slog.String("component", "docker_monitor")),
		ctx:             ctx,
		cancel:          cancel,
		netRulesManager: netRulesManager,
		opts:            opts,
		fatalErr:        make(chan error, 1),
	}
	if opts.TerminalXClient != nil {
		monitor.terminalXEnforce = opts.TerminalXClient.enforceTerminalXNetworkPolicy
		monitor.terminalXQuarantine = opts.TerminalXClient.quarantineTerminalXContainers
	}
	return monitor
}

func (dm *DockerMonitor) Stop() {
	dm.cancel()
}

func (dm *DockerMonitor) Start() error {
	// Start periodic reconciliation
	go dm.reconcilerLoop()

	// Main monitoring loop
	for {
		select {
		case <-dm.ctx.Done():
			dm.log.Info("Context cancelled, stopping monitor...")
			return dm.ctx.Err()

		default:
			if err := dm.monitorEvents(); err != nil {
				if isConnectionError(err) {
					dm.log.Warn("Events stream ended", "error", err)
					dm.log.Info("Reopening events stream in 2 seconds...")
					time.Sleep(2 * time.Second)
					continue
				} else {
					dm.log.Error("Fatal error in monitoring", "error", err)
					return err
				}
			}
		}
	}
}

// isConnectionError checks if the error is related to connection loss
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// io.EOF is the normal way the Docker Events stream ends
	if err == io.EOF {
		return true
	}

	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no such host") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "unexpected EOF") ||
		strings.Contains(errStr, "Cannot connect to the Docker daemon")
}

// monitorEvents handles the actual event monitoring with proper error handling
func (dm *DockerMonitor) monitorEvents() error {
	// Create event filters to monitor only container create and stop events
	eventFilters := events.ListOptions{
		Filters: filters.NewArgs(
			filters.Arg("type", "container"),
			filters.Arg("type", "network"),
			filters.Arg("event", "start"),
			filters.Arg("event", "restart"),
			filters.Arg("event", "update"),
			filters.Arg("event", "connect"),
			filters.Arg("event", "disconnect"),
			filters.Arg("event", "stop"),
			filters.Arg("event", "kill"),
			filters.Arg("event", "destroy"),
		),
	}

	// Start listening for events
	eventsChan, errsChan := dm.apiClient.Events(dm.ctx, eventFilters)

	// Reconnection established successfully
	if err := dm.reconcileTerminalXBlockedContainers(); err != nil {
		return dm.failTerminalXClosed(err)
	}
	dm.reconcileNetworkRules("filter", "DOCKER-USER")
	dm.reconcileNetworkRules("mangle", "PREROUTING")

	for {
		select {
		case event, ok := <-eventsChan:
			if !ok {
				return io.EOF
			}
			dm.log.Debug("Received event", "event", event)
			if err := dm.handleContainerEvent(event); err != nil {
				return dm.failTerminalXClosed(err)
			}

		case err, ok := <-errsChan:
			if !ok {
				return io.EOF
			}
			if err != nil {
				dm.log.Warn("Events stream ended", "error", err)
				return err
			}

		case <-dm.ctx.Done():
			return dm.ctx.Err()

		case err := <-dm.fatalErr:
			return err
		}
	}
}

func (dm *DockerMonitor) handleContainerEvent(event events.Message) error {
	containerID := event.Actor.ID
	action := event.Action
	if dm.opts.TerminalXHardened && event.Type == events.NetworkEventType {
		if action != events.ActionConnect && action != events.ActionDisconnect {
			return nil
		}
		containerID = event.Actor.Attributes["container"]
		if containerID == "" {
			return fmt.Errorf("terminalx hardened monitor rejected network event identity")
		}
		if action == events.ActionDisconnect {
			return dm.handleTerminalXNetworkDisconnect(containerID)
		}
		return dm.inspectAndEnforceTerminalXContainer(containerID)
	}

	switch action {
	case events.ActionStart, events.ActionRestart, events.ActionUpdate:
		if dm.opts.TerminalXHardened {
			return dm.inspectAndEnforceTerminalXContainer(containerID)
		}
		ct, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			if dm.opts.TerminalXHardened {
				return fmt.Errorf("error inspecting started container: %w", err)
			}
			dm.log.Error("Error inspecting container", "error", err)
			return nil
		}
		if len(containerID) < 12 {
			return fmt.Errorf("container event identity is invalid")
		}
		shortContainerID := containerID[:12]
		err = dm.netRulesManager.AssignNetworkRules(shortContainerID, GetContainerIpAddress(dm.ctx, &ct))
		if err != nil {
			if dm.opts.TerminalXHardened {
				return fmt.Errorf("error assigning network rules: %w", err)
			}
			dm.log.Error("Error assigning network rules", "error", err)
		}
	case events.ActionStop:
	case events.ActionKill:
		if dm.opts.TerminalXHardened {
			// A stop/kill event is not proof that every process is gone, and event
			// delivery may interleave with a subsequent restart. Keep the DROP
			// assignment until Docker confirms destruction of the container.
			return nil
		}
		if len(containerID) < 12 {
			return fmt.Errorf("container event identity is invalid")
		}
		shortContainerID := containerID[:12]
		err := dm.netRulesManager.UnassignNetworkRules(shortContainerID)
		if err != nil {
			dm.log.Error("Error unassigning network rules", "error", err)
		}
		err = dm.netRulesManager.RemoveNetworkLimiter(shortContainerID)
		if err != nil {
			dm.log.Error("Error removing network limiter", "error", err)
		}
	case events.ActionDestroy:
		if len(containerID) < 12 {
			return fmt.Errorf("container event identity is invalid")
		}
		shortContainerID := containerID[:12]
		err := dm.netRulesManager.DeleteNetworkRules(shortContainerID)
		if err != nil {
			dm.log.Error("Error deleting network rules", "error", err)
		}
		if dm.opts.OnDestroyEvent != nil {
			go dm.opts.OnDestroyEvent(dm.ctx)
		}
	}
	return nil
}

func (dm *DockerMonitor) handleTerminalXNetworkDisconnect(containerID string) error {
	if len(containerID) < 12 {
		return fmt.Errorf("terminalx hardened monitor rejected container identity")
	}
	inspected, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
	if err != nil {
		// Docker normally detaches the network while removing a container. Keep
		// its existing DROP assignment until the destroy event performs cleanup.
		if errdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("terminalx hardened monitor could not inspect disconnected container: %w", err)
	}
	if inspected.State == nil || !inspected.State.Running {
		return nil
	}
	// A running sandbox losing or changing its only pinned network is drift,
	// not lifecycle cleanup, and must enter the global fail-closed path.
	return dm.enforceTerminalXBlockedContainer(&inspected)
}

func (dm *DockerMonitor) inspectAndEnforceTerminalXContainer(containerID string) error {
	if len(containerID) < 12 {
		return fmt.Errorf("terminalx hardened monitor rejected container identity")
	}
	inspected, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
	if err != nil {
		return fmt.Errorf("terminalx hardened monitor could not inspect container: %w", err)
	}
	return dm.enforceTerminalXBlockedContainer(&inspected)
}

func (dm *DockerMonitor) reconcileTerminalXBlockedContainers() error {
	if !dm.opts.TerminalXHardened {
		return nil
	}
	containers, err := dm.apiClient.ContainerList(dm.ctx, container.ListOptions{
		All: true,
	})
	if err != nil {
		return fmt.Errorf("failed to list terminalx hardened containers: %w", err)
	}
	for _, summary := range containers {
		inspected, err := dm.apiClient.ContainerInspect(dm.ctx, summary.ID)
		if err != nil {
			return fmt.Errorf("failed to inspect terminalx hardened container: %w", err)
		}
		if err := dm.enforceTerminalXBlockedContainer(&inspected); err != nil {
			return err
		}
	}
	return nil
}

func (dm *DockerMonitor) enforceTerminalXBlockedContainer(inspected *container.InspectResponse) error {
	if dm.terminalXEnforce == nil {
		return fmt.Errorf("terminalx hardened monitor validator is unavailable")
	}
	if err := dm.terminalXEnforce(dm.ctx, inspected); err != nil {
		return fmt.Errorf("terminalx hardened monitor could not enforce network policy: %w", err)
	}
	return nil
}

func (dm *DockerMonitor) failTerminalXClosed(cause error) error {
	if !dm.opts.TerminalXHardened || dm.terminalXQuarantine == nil {
		return cause
	}
	quarantineCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return dm.terminalXQuarantine(quarantineCtx, cause)
}

// reconcileNetworkRules is called when reconnection is established
func (dm *DockerMonitor) reconcileNetworkRules(table string, chain string) {
	// List all DOCKER-USER rules that jump to Daytona chains
	rules, err := dm.netRulesManager.ListDaytonaRules(table, chain)
	if err != nil {
		dm.log.Error("Error listing Daytona rules", "error", err)
		return
	}

	for _, rule := range rules {
		// Parse the rule to extract chain name and source IP
		args, err := netrules.ParseRuleArguments(rule)
		if err != nil {
			dm.log.Error("Error parsing rule", "rule", rule, "error", err)
			continue
		}

		// Find the chain name and source IP from the rule arguments
		var chainName, sourceIP string
		for i, arg := range args {
			if arg == "-j" && i+1 < len(args) {
				chainName = args[i+1]
			}
			if arg == "-s" && i+1 < len(args) {
				sourceIP = args[i+1]
			}
		}

		if chainName == "" || sourceIP == "" {
			dm.log.Warn("Could not extract chain name or source IP from rule", "rule", rule)
			continue
		}

		// Extract container ID from chain name (remove DAYTONA-SB- prefix)
		containerID := strings.TrimPrefix(chainName, "DAYTONA-SB-")
		if containerID == chainName {
			dm.log.Warn("Invalid chain name format", "chainName", chainName)
			continue
		}

		// Inspect the container to get its current IP
		container, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			dm.log.Error("Error inspecting container", "containerID", containerID, "error", err)
			if dm.opts.TerminalXHardened {
				// Inspection ambiguity must retain the existing DROP assignment.
				continue
			}
			// Container doesn't exist, unassign the rules
			if err := dm.netRulesManager.UnassignNetworkRules(containerID); err != nil {
				dm.log.Error("Error unassigning rules for non-existent container", "containerID", containerID, "error", err)
			} else {
				dm.log.Info("Unassigned rules for non-existent container", "containerID", containerID)
			}
			continue
		}

		ipAddress := GetContainerIpAddress(dm.ctx, &container)

		// Check if the container IP matches the rule's source IP
		// Handle CIDR notation by extracting just the IP part
		ruleIP := sourceIP
		if strings.Contains(sourceIP, "/") {
			ruleIP = strings.Split(sourceIP, "/")[0]
		}

		if ipAddress != ruleIP {
			dm.log.Warn("IP mismatch for container", "containerID", containerID, "ruleIP", ruleIP, "containerIP", ipAddress)

			// Delete only this specific mismatched rule
			if err := dm.netRulesManager.DeleteChainRule(table, chain, rule); err != nil {
				dm.log.Error("Error deleting mismatched rule for container", "containerID", containerID, "error", err)
			} else {
				dm.log.Info("Deleted mismatched rule for container", "containerID", containerID)
			}
		}
	}
}

// reconcileChains removes orphaned chains for non-existent containers
func (dm *DockerMonitor) reconcileChains(table string) {
	// List all chains that start with DAYTONA-SB-
	chains, err := dm.netRulesManager.ListDaytonaChains(table)
	if err != nil {
		dm.log.Error("Error listing Daytona chains", "error", err)
		return
	}

	for _, chain := range chains {
		// Extract container ID from chain name (remove DAYTONA-SB- prefix)
		containerID := strings.TrimPrefix(chain, "DAYTONA-SB-")
		if containerID == chain {
			dm.log.Warn("Invalid chain name format", "chain", chain)
			continue
		}

		// Check if the container exists
		_, err := dm.apiClient.ContainerInspect(dm.ctx, containerID)
		if err != nil {
			if dm.opts.TerminalXHardened {
				// A transient inspect failure is not proof that a DROP chain is orphaned.
				continue
			}
			dm.log.Info("Container does not exist, deleting chain", "containerID", containerID, "chain", chain)

			// Delete the orphaned chain
			if err := dm.netRulesManager.ClearAndDeleteChain(table, chain); err != nil {
				dm.log.Error("Error deleting orphaned chain", "chain", chain, "error", err)
			} else {
				dm.log.Info("Deleted orphaned chain", "chain", chain)
			}
		}
	}
}

// reconcilerLoop runs reconciliation every minute
func (dm *DockerMonitor) reconcilerLoop() {
	dm.reconcilerLoopAt(1 * time.Minute)
}

func (dm *DockerMonitor) reconcilerLoopAt(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			return
		case <-ticker.C:
			dm.log.Debug("Reconciling network rules")
			if err := dm.reconcileTerminalXBlockedContainers(); err != nil {
				fatalErr := dm.failTerminalXClosed(err)
				dm.log.Error("Failed to reconcile TerminalX blocked containers", "error", fatalErr)
				select {
				case dm.fatalErr <- fatalErr:
				case <-dm.ctx.Done():
				}
				return
			}
			dm.reconcileNetworkRules("filter", "DOCKER-USER")
			dm.reconcileNetworkRules("mangle", "PREROUTING")
			dm.reconcileChains("filter")
			dm.reconcileChains("mangle")
		}
	}
}
