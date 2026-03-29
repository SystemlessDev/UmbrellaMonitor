package main

import (
	"github.com/tailscale/wf"
)

// https://tailscale.com/blog/windows-firewall
func SetFirewallRules(firewallSession *wf.Session, firewallAction wf.Action, firewallConfiguration []ConfigurationRule) []error {
	var errorarray []error

	for _, program := range firewallConfiguration {
		switch firewallAction {
		case wf.ActionBlock:
			appID, err := wf.AppID(program.ProgramPath)
			if err != nil {
				// Program not found. Ignoring it.
				continue
			}
			err = firewallSession.AddRule(&wf.Rule{
				Name:   program.RuleName,
				Layer:  wf.LayerALEAuthConnectV4,
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

			errorarray = append(errorarray, err)

		case wf.ActionPermit:
			err := firewallSession.DeleteRule(wf.RuleID(program.RuleGUID))
			errorarray = append(errorarray, err)

		}
	}
	return errorarray
}
