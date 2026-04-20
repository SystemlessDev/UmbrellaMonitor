package main

import (
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

// https://tailscale.com/blog/windows-firewall
func SetFirewallRule(firewallSession *wf.Session, ruleConfig ConfigurationRule, ruleLayer wf.LayerID) (wf.RuleID, error) {
	guid, _ := windows.GenerateGUID()
	ruleId := wf.RuleID(guid)

	appID, err := wf.AppID(ruleConfig.ProgramPath)
	if err != nil {
		return ruleId, err
		// Program not found. Ignoring it.
	}

	rule := &wf.Rule{
		Name:   ruleConfig.RuleName,
		Layer:  ruleLayer,
		ID:     ruleId,
		Weight: 100,
		Conditions: []*wf.Match{{
			Field: wf.FieldALEAppID,
			Op:    wf.MatchTypeEqual,
			Value: appID,
		}},
		Action: wf.ActionBlock,
	}

	err = firewallSession.AddRule(rule)

	return ruleId, err
}

func DeleteFirewallRule(firewallSession *wf.Session, ruleID wf.RuleID) error {
	return firewallSession.DeleteRule(ruleID)
}
