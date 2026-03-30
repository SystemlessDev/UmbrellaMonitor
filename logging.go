package main

import (
	"log"

	"golang.org/x/sys/windows/svc/eventlog"
)

var eventlogger *eventlog.Log

func init_eventlog() {
	const supports = eventlog.Error | eventlog.Warning | eventlog.Info
	err := eventlog.InstallAsEventCreate("umbrellamonitor", supports)
	if err != nil {
		log.Println("Failed to install registry keys: ", err)
	}
	eventlogger, err = eventlog.Open("umbrellamonitor")
	if err != nil {
		log.Panicln("Failed to open umbrella monitor event log", err)
	}
}
