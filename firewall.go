package main

import (
	"fmt"
	"strings"

	"github.com/tailscale/wf"
)

// https://tailscale.com/blog/windows-firewall
func SetFirewallRules(firewallSession *wf.Session, firewallConfiguration []ConfigurationRule, firewallLayer wf.LayerID) []error {
	var errorarray []error
	var prefix string
	if firewallLayer == wf.LayerALEAuthConnectV4 {
		prefix = "UM_IPV4_"
	} else {
		prefix = "UM_IPV6_"
	}

	for _, program := range firewallConfiguration {
		appID, err := wf.AppID(program.ProgramPath)
		if err != nil {
			// Program not found. Ignoring it.
			continue
		}
		err = firewallSession.AddRule(&wf.Rule{
			Name:   prefix + program.RuleName,
			Layer:  firewallLayer,
			ID:     wf.RuleID(program.RuleGUID),
			Weight: 100,
			Conditions: []*wf.Match{
				{
					Field: wf.FieldALEAppID,
					Op:    wf.MatchTypeEqual,
					Value: appID,
				},
			},
			Action: wf.ActionBlock,
		})
		if err != nil {
			errorarray = append(errorarray, err)
		}

	}
	return errorarray
}

func DeleteFirewallRules(firewallSession *wf.Session, rulePrefix string) {
	rules, err := firewallSession.Rules()
	if err != nil {
		// TODO missing logging
		return
	}
	for _, rule := range rules {
		if strings.HasPrefix(rule.Name, rulePrefix) {
			fmt.Println("Deleting rule " + rule.Name)
			firewallSession.DeleteRule(rule.ID)
		}
	}
}
