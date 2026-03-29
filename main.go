package main

import (
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/google/winops/winlog"
	"github.com/google/winops/winlog/wevtapi"
	"github.com/tailscale/wf"
	"golang.org/x/sys/windows"
)

const WINDOWS_ENGLISH_LANGUAGE = 1033

var ParsedConfig Configuration

// Source:
// https://github.com/google/winops/blob/master/winlog/examples/pullsub/pullsub.go
func main() {
	logOutput, err := CreateLogFile()
	if err != nil {
		os.Exit(1)
	}
	log.SetOutput(logOutput)

	ParsedConfig, err := ReadConfiguration()
	if err != nil {
		log.Fatalln("ReadConfiguration(): \n", err)
	}

	// Killswitch
	if ParsedConfig.BlockingEnabled == false {
		for {
			log.Println("Killswitch active")
			time.Sleep(10 * time.Second)
		}
	}

	// Dynamic makes the firewall rules die together with the program
	firewallSession, err := wf.New(&wf.Options{
		Name:    "UmbrellaMonitor",
		Dynamic: true,
	})
	if err != nil {
		log.Fatalln("wf.New(): %w", err)
	}

	winlogConfig, err := winlog.DefaultSubscribeConfig()
	if err != nil {
		log.Fatalln("winlog.DefaultSubscribeConfig(): \n", err)
	}

	// Possible race condition:
	// In theory, someone could crash this process and do the Umbrella trick. That would, in theory, revert to the old behavior.
	winlogConfig.Flags = wevtapi.EvtSubscribeToFutureEvents
	query, err := CreateEventlogQuery(map[string]string{ParsedConfig.EventlogMonitor: "*"})
	if err != nil {
		log.Fatalln("CreateEventlogQuery(): \n", err)
	}
	winlogConfig.Query = query

	subscription, err := winlog.Subscribe(winlogConfig)
	if err != nil {
		log.Fatalln("winlog.Subscribe(): \n", err)
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
				log.Println("winlog.GetRenderedEvents failed: \n", err)
				break
			}
			var firewallAction wf.Action
			for _, event := range renderedEvents {
				if strings.Contains(event, ParsedConfig.AllowString) {
					log.Println("Event unblocking firewall: \n", event)
					firewallAction = wf.ActionPermit
				} else if strings.Contains(event, ParsedConfig.BlockString) {
					log.Println("Event blocking firewall: \n", event)
					firewallAction = wf.ActionBlock
				}
			}

			if (firewallAction == wf.ActionPermit) || (firewallAction == wf.ActionBlock) {
				errorarray := SetFirewallRules(firewallSession, firewallAction, ParsedConfig.RuleConfiguration)
				if len(errorarray) > 0 {
					log.Println(errorarray)
				}
			}
		}
	}
}
