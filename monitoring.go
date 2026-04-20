package main

import (
	"fmt"
	"log"
	"strings"
	"syscall"

	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

type RuleState struct {
	IPv4 wf.Action
	IPv6 wf.Action
}

type ActiveFirewallRules struct {
	IPv4Rules []wf.RuleID
	IPv6Rules []wf.RuleID
}

var ActiveRules ActiveFirewallRules

// Source:
// https://github.com/google/winops/blob/master/winlog/examples/pullsub/pullsub.go
func eventlog_read_loop() {
	var err error

	// Dynamic makes the firewall rules die together with the program
	firewallSession, err := wf.New(&wf.Options{
		Name:    "UmbrellaMonitor",
		Dynamic: true,
	})
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("wf.New(): %v", err))
	}

	winlogConfig, err := winlog.DefaultSubscribeConfig()
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("winlog.DefaultSubscribeConfig(): %v", err))
	}

	// Possible race condition:
	// In theory, someone could crash this process and do the Umbrella trick. That would, in theory, revert to the old behavior.
	winlogConfig.Flags = wevtapi.EvtSubscribeToFutureEvents
	query, err := CreateEventlogQuery(map[string]string{PARSED_CONFIGURATION.EventlogMonitor: "*"})
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("CreateEventlogQuery(): %v", err))
	}
	winlogConfig.Query = query

	subscription, err := winlog.Subscribe(winlogConfig)
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("winlog.Subscribe(): %v", err))
	}

	defer winlog.Close(subscription)

	publisherCache := make(map[string]windows.Handle)
	defer func() {
		for _, h := range publisherCache {
			winlog.Close(h)
		}
	}()

	for {
		// https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
		status, err := windows.WaitForSingleObject(winlogConfig.SignalEvent, windows.INFINITE)

		if err != nil {
			log.Println("windows.WaitForSingleObject() \n", err)
			break
		}
		if status == syscall.WAIT_OBJECT_0 {
			// Enumerate and render available events in blocks of up to 100.
			renderedEvents, err := winlog.GetRenderedEvents(winlogConfig, publisherCache, subscription, 100, WINDOWS_ENGLISH_LANGUAGE)
			// If no more events are available reset the subscription signal.
			if err == syscall.Errno(windows.ERROR_NO_MORE_ITEMS) {
				windows.ResetEvent(winlogConfig.SignalEvent)
			} else if err != nil {
				eventlogger.Warning(200, fmt.Sprintf("winlog.GetRenderedEvents returned error: %v", err))
				break
			}
			var firewallAction RuleState
			for _, event := range renderedEvents {
				if strings.Contains(event, PARSED_CONFIGURATION.AllowStringV4) {
					eventlogger.Info(100, fmt.Sprintf("Event unblocking firewall: %v", event))
					firewallAction.IPv4 = wf.ActionPermit
				} else if strings.Contains(event, PARSED_CONFIGURATION.BlockStringV4) {
					eventlogger.Info(100, fmt.Sprintf("Event blocking firewall: %v", event))
					firewallAction.IPv4 = wf.ActionBlock
				}
				if strings.Contains(event, PARSED_CONFIGURATION.AllowStringV6) {
					eventlogger.Info(100, fmt.Sprintf("Event unblocking firewall: %v", event))
					firewallAction.IPv6 = wf.ActionPermit
				} else if strings.Contains(event, PARSED_CONFIGURATION.BlockStringV6) {
					eventlogger.Info(100, fmt.Sprintf("Event blocking firewall: %v", event))
					firewallAction.IPv6 = wf.ActionBlock
				}
			}

			switch firewallAction.IPv4 {
			case wf.ActionPermit:
				currentRules := []wf.RuleID{}
				for _, ruleID := range ActiveRules.IPv4Rules {
					err = DeleteFirewallRule(firewallSession, ruleID)
					if err != nil {
						eventlogger.Warning(100, fmt.Sprintf("Got error while deleting firewall rule: %v", err))
						currentRules = append(currentRules, ruleID)
					}
				}
				ActiveRules.IPv4Rules = currentRules

			case wf.ActionBlock:
				for _, rule := range PARSED_CONFIGURATION.RuleConfigurations {
					ruleId, err := SetFirewallRule(firewallSession, rule, wf.LayerALEAuthConnectV4)
					if err != nil {
						eventlogger.Warning(100, fmt.Sprintf("Got error while setting firewall rule: %v", err))
						continue
					}
					ActiveRules.IPv4Rules = append(ActiveRules.IPv4Rules, ruleId)
				}

			default:
				// ignore
			}

			switch firewallAction.IPv6 {
			case wf.ActionPermit:
				currentRules := []wf.RuleID{}
				for _, ruleID := range ActiveRules.IPv6Rules {
					err = DeleteFirewallRule(firewallSession, ruleID)
					// If we experience an error we don't remove the rule from the array.
					if err != nil {
						eventlogger.Warning(100, fmt.Sprintf("Got error while deleting firewall rule: %v", err))
						currentRules = append(currentRules, ruleID)
					}
				}
				ActiveRules.IPv6Rules = currentRules
			case wf.ActionBlock:
				for _, rule := range PARSED_CONFIGURATION.RuleConfigurations {
					ruleId, err := SetFirewallRule(firewallSession, rule, wf.LayerALEAuthConnectV6)
					if err != nil {
						eventlogger.Warning(100, fmt.Sprintf("Got error while setting firewall rule: %v", err))
						continue
					}
					ActiveRules.IPv6Rules = append(ActiveRules.IPv6Rules, ruleId)
				}

			default:
				// ignore
			}
		}
	}
}
