// Copyright 2026 TerminalX contributors
// SPDX-License-Identifier: AGPL-3.0

package netrules

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type terminalXRulePositionerFake struct {
	rules      []string
	operations []string
}

func (fake *terminalXRulePositionerFake) Insert(_ string, chain string, pos int, rulespec ...string) error {
	if pos != 1 {
		return fmt.Errorf("unexpected position %d", pos)
	}
	fake.operations = append(fake.operations, "insert "+strings.Join(rulespec, " "))
	rule := "-A " + chain + " " + strings.Join(rulespec, " ")
	fake.rules = append([]string{rule}, fake.rules...)
	return nil
}

func (fake *terminalXRulePositionerFake) List(_, _ string) ([]string, error) {
	return append([]string(nil), fake.rules...), nil
}

func TestFirstEffectiveRuleDrops(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		rules []string
		want  bool
	}{
		{name: "empty", rules: nil, want: false},
		{name: "declaration then drop", rules: []string{"-N DAYTONA-SB-abc", "-A DAYTONA-SB-abc -j DROP -p all"}, want: true},
		{name: "drop with normalized order", rules: []string{"-A DAYTONA-SB-abc -p all -j DROP"}, want: true},
		{name: "conditional destination drop", rules: []string{"-A DAYTONA-SB-abc -d 10.0.0.0/8 -j DROP"}, want: false},
		{name: "conditional source drop", rules: []string{"-A DAYTONA-SB-abc -s 172.20.0.2 -j DROP"}, want: false},
		{name: "allow before drop", rules: []string{"-A DAYTONA-SB-abc -d 10.0.0.0/8 -j RETURN", "-A DAYTONA-SB-abc -j DROP"}, want: false},
		{name: "unrelated first rule", rules: []string{"-A DAYTONA-SB-abc -m conntrack --ctstate ESTABLISHED -j ACCEPT"}, want: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := firstEffectiveRuleDrops(test.rules); got != test.want {
				t.Fatalf("firstEffectiveRuleDrops() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestHostRuleCommentUsesStableContainerIdentity(t *testing.T) {
	t.Parallel()
	if got := hostRuleComment("abc123"); got != "terminalx-host-abc123" {
		t.Fatalf("hostRuleComment() = %q", got)
	}
	if got := hostRuleComment("DAYTONA-SB-abc123"); got != "terminalx-host-abc123" {
		t.Fatalf("prefixed hostRuleComment() = %q", got)
	}
}

func TestPositionTerminalXRulesAtHeadRepairsReorderedRulesWithoutDeleting(t *testing.T) {
	t.Parallel()
	desired := [][]string{
		{"-s", "172.20.0.2", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-m", "comment", "--comment", "terminalx-host-abc", "-j", "ACCEPT"},
		{"-s", "172.20.0.2", "-m", "comment", "--comment", "terminalx-host-abc", "-j", "DROP"},
	}
	fake := &terminalXRulePositionerFake{rules: []string{
		"-A INPUT -j ACCEPT",
		"-A INPUT -s 172.20.0.2/32 -m comment --comment terminalx-host-abc -j DROP",
		"-A INPUT -s 172.20.0.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment terminalx-host-abc -j ACCEPT",
	}}
	if err := positionTerminalXRulesAtHead(fake, "filter", "INPUT", desired); err != nil {
		t.Fatalf("position rules: %v", err)
	}
	wantPrefix := []string{
		"-A INPUT " + strings.Join(desired[0], " "),
		"-A INPUT " + strings.Join(desired[1], " "),
	}
	if !reflect.DeepEqual(fake.rules[:2], wantPrefix) {
		t.Fatalf("head rules = %v, want %v", fake.rules[:2], wantPrefix)
	}
	if len(fake.operations) != 2 || !strings.HasSuffix(fake.operations[0], "-j DROP") || !strings.HasSuffix(fake.operations[1], "-j ACCEPT") {
		t.Fatalf("unsafe operation order: %v", fake.operations)
	}
	for _, operation := range fake.operations {
		if strings.HasPrefix(operation, "delete") || strings.HasPrefix(operation, "clear") {
			t.Fatalf("destructive operation before safe prefix: %v", fake.operations)
		}
	}
}

func TestPositionTerminalXRulesAtHeadIsStableWhenAlreadyPinned(t *testing.T) {
	t.Parallel()
	desired := [][]string{{"-j", "DAYTONA-SB-abc", "-s", "172.20.0.2", "-p", "all"}}
	fake := &terminalXRulePositionerFake{rules: []string{
		"-A DOCKER-USER -s 172.20.0.2/32 -j DAYTONA-SB-abc",
	}}
	if err := positionTerminalXRulesAtHead(fake, "filter", "DOCKER-USER", desired); err != nil {
		t.Fatalf("position rules: %v", err)
	}
	if len(fake.operations) != 0 {
		t.Fatalf("stable prefix was duplicated: %v", fake.operations)
	}
}

func TestTerminalXRuleComparisonAcceptsRealIptablesCanonicalization(t *testing.T) {
	t.Parallel()
	tests := []struct {
		actual   string
		expected string
	}{
		{
			actual:   "-s 172.20.0.2/32 -j DAYTONA-SB-abc",
			expected: "-j DAYTONA-SB-abc -s 172.20.0.2 -p all",
		},
		{
			actual:   "-s 172.20.0.2/32 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment terminalx-host-abc -j ACCEPT",
			expected: "-s 172.20.0.2 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment terminalx-host-abc -j ACCEPT",
		},
	}
	for _, test := range tests {
		if !sameTerminalXRule(strings.Fields(test.actual), strings.Fields(test.expected)) {
			t.Fatalf("canonical rule did not match: %q", test.actual)
		}
	}
}
