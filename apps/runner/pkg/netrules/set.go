// Copyright 2025 Daytona Platforms Inc.
// SPDX-License-Identifier: AGPL-3.0

package netrules

import "strings"

type terminalXRulePositioner interface {
	Insert(table, chain string, pos int, rulespec ...string) error
	List(table, chain string) ([]string, error)
}

// SetBlockedNetworkRules installs a fail-closed chain without clearing a live
// chain first.  If a stale chain contains broader rules, a DROP is inserted at
// its head before the DOCKER-USER jump is assigned.  Reconciliation therefore
// never creates the post-start or clear-and-rebuild egress window tolerated by
// the general Daytona allow-list path.
func (manager *NetRulesManager) SetBlockedNetworkRules(name string, sourceIp string) error {
	chainName := formatChainName(name)
	comment := hostRuleComment(name)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	if err := manager.ipt.NewChain("filter", chainName); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}
	rules, err := manager.ipt.List("filter", chainName)
	if err != nil {
		return err
	}
	if !firstEffectiveRuleDrops(rules) {
		if err := manager.ipt.Insert("filter", chainName, 1, "-j", "DROP", "-p", "all"); err != nil {
			return err
		}
	}
	// DOCKER-USER covers forwarded traffic, but traffic addressed to a runner
	// host service traverses INPUT instead.  Install DROP first, then place the
	// established-response exception ahead of it.  A Sandbox can therefore
	// answer a runner-initiated daemon request but cannot initiate a host call.
	acceptHostReplies := []string{
		"-s", sourceIp, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED",
		"-m", "comment", "--comment", comment, "-j", "ACCEPT",
	}
	dropHostCalls := []string{
		"-s", sourceIp, "-m", "comment", "--comment", comment, "-j", "DROP",
	}
	if err := positionTerminalXRulesAtHead(manager.ipt, "filter", "INPUT",
		[][]string{acceptHostReplies, dropHostCalls}); err != nil {
		return err
	}
	return positionTerminalXRulesAtHead(manager.ipt, "filter", "DOCKER-USER",
		[][]string{{"-j", chainName, "-s", sourceIp, "-p", "all"}})
}

// positionTerminalXRulesAtHead inserts a complete fail-closed prefix before it
// leaves any older copies in place until container destruction. Unlike
// InsertUnique, this repairs a rule that another firewall manager moved below
// an ACCEPT/RETURN rule without creating a delete-before-insert exposure window.
func positionTerminalXRulesAtHead(
	ipt terminalXRulePositioner,
	table string,
	chain string,
	desired [][]string,
) error {
	rules, err := ipt.List(table, chain)
	if err != nil {
		return err
	}
	effective := make([][]string, 0, len(desired))
	for _, rule := range rules {
		arguments, err := ParseRuleArguments(rule)
		if err != nil {
			continue
		}
		effective = append(effective, arguments)
		if len(effective) == len(desired) {
			break
		}
	}
	if len(effective) == len(desired) {
		matches := true
		for index := range desired {
			if !sameTerminalXRule(effective[index], desired[index]) {
				matches = false
				break
			}
		}
		if matches {
			return nil
		}
	}

	for index := len(desired) - 1; index >= 0; index-- {
		if err := ipt.Insert(table, chain, 1, desired[index]...); err != nil {
			return err
		}
	}
	return nil
}

func sameTerminalXRule(actual []string, expected []string) bool {
	actualRule, actualOK := parseTerminalXRule(actual)
	expectedRule, expectedOK := parseTerminalXRule(expected)
	return actualOK && expectedOK && actualRule == expectedRule
}

type terminalXRule struct {
	source    string
	protocol  string
	jump      string
	comment   string
	conntrack string
}

func parseTerminalXRule(arguments []string) (terminalXRule, bool) {
	parsed := terminalXRule{protocol: "all"}
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if index+1 >= len(arguments) {
			return terminalXRule{}, false
		}
		value := arguments[index+1]
		switch argument {
		case "-s":
			parsed.source = strings.TrimSuffix(value, "/32")
		case "-p":
			parsed.protocol = value
		case "-j":
			parsed.jump = value
		case "--comment":
			parsed.comment = value
		case "--ctstate":
			parsed.conntrack = normalizeTerminalXConntrack(value)
		case "-m":
			if value != "comment" && value != "conntrack" {
				return terminalXRule{}, false
			}
		default:
			return terminalXRule{}, false
		}
		index++
	}
	return parsed, parsed.source != "" && parsed.jump != ""
}

func normalizeTerminalXConntrack(value string) string {
	states := strings.Split(value, ",")
	if len(states) == 2 &&
		((states[0] == "ESTABLISHED" && states[1] == "RELATED") ||
			(states[0] == "RELATED" && states[1] == "ESTABLISHED")) {
		return "ESTABLISHED,RELATED"
	}
	return value
}

func firstEffectiveRuleDrops(rules []string) bool {
	for _, rule := range rules {
		args, err := ParseRuleArguments(rule)
		if err != nil {
			continue
		}
		return isUnconditionalDrop(args)
	}
	return false
}

func isUnconditionalDrop(arguments []string) bool {
	sawDrop := false
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "-p":
			if index+1 >= len(arguments) || arguments[index+1] != "all" {
				return false
			}
			index++
		case "-j":
			if index+1 >= len(arguments) || arguments[index+1] != "DROP" || sawDrop {
				return false
			}
			sawDrop = true
			index++
		default:
			return false
		}
	}
	return sawDrop
}

// SetNetworkRules creates and configures network rules for a container
func (manager *NetRulesManager) SetNetworkRules(name string, sourceIp string, networkAllowList string) error {
	// Parse the allowed networks
	allowedNetworks, err := parseCidrNetworks(networkAllowList)
	if err != nil {
		return err
	}

	// Add prefix to chain name
	chainName := formatChainName(name)

	manager.mu.Lock()
	defer manager.mu.Unlock()

	// Create the chain (ignores if already exists)
	err = manager.ipt.NewChain("filter", chainName)
	if err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}

	// Clear existing rules to ensure clean state
	if err := manager.ipt.ClearChain("filter", chainName); err != nil {
		return err
	}

	// Add rules to allow traffic from the specified networks
	for _, network := range allowedNetworks {
		if err := manager.ipt.AppendUnique("filter", chainName, "-j", "RETURN", "-d", network.String(), "-p", "all"); err != nil {
			return err
		}
	}

	// Add a final rule to block all other traffic
	if err := manager.ipt.AppendUnique("filter", chainName, "-j", "DROP", "-p", "all"); err != nil {
		return err
	}

	// Assign the rules to the container (atomic within the same mutex)
	if err := manager.ipt.InsertUnique("filter", "DOCKER-USER", 1, "-j", chainName, "-s", sourceIp, "-p", "all"); err != nil {
		return err
	}

	return nil
}
