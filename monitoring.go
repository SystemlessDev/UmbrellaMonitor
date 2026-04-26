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

// Source:
// https://github.com/google/winops/blob/master/winlog/examples/pullsub/pullsub.go
func eventlog_read_loop() {
	var err error
	var ParsedConfig Configuration
	ParsedConfig, err = ReadConfiguration()
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("ReadConfiguration(): %v", err))
		syscall.Exit(1)
	}

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
	query, err := CreateEventlogQuery(map[string]string{ParsedConfig.EventlogMonitor: "*"})
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
			var firewallAction wf.Action
			for _, event := range renderedEvents {
				if strings.Contains(event, ParsedConfig.AllowString) {
					eventlogger.Info(100, fmt.Sprintf("Event unblocking firewall: %v", event))
					firewallAction = wf.ActionPermit
				} else if strings.Contains(event, ParsedConfig.BlockString) {
					eventlogger.Info(100, fmt.Sprintf("Event blocking firewall: %v", event))
					firewallAction = wf.ActionBlock
				}
			}

			if (firewallAction == wf.ActionPermit) || (firewallAction == wf.ActionBlock) {
				errorarray := SetFirewallRules(firewallSession, firewallAction, ParsedConfig.RuleConfigurations)
				if len(errorarray) > 0 {
					eventlogger.Warning(100, fmt.Sprintf("Got error while setting firewall rules: %v", errorarray))
				}
			}
		}
	}
}
