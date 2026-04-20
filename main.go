package main

import (
	"fmt"
	"log"
	"syscall"

	"golang.org/x/sys/windows/svc"
)

const WINDOWS_ENGLISH_LANGUAGE = 1033

var PARSED_CONFIGURATION Configuration

func main() {
	var err error
	init_eventlog()
	PARSED_CONFIGURATION, err = ReadConfiguration()
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("ReadConfiguration(): %v", err))
		syscall.Exit(1)
	}

	inService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatalf("failed to determine if we are running in service: %v", err)
	}
	if inService {
		err := svc.Run("umbrellaservice", &umbrellaService{})
		if err != nil {
			log.Fatalf("service failed: %v", err)
		}
	} else {
		eventlog_read_loop()
	}
}
