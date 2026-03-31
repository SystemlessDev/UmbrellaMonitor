package main

import (
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
)

const WINDOWS_ENGLISH_LANGUAGE = 1033

func main() {
	init_eventlog()
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
		go eventlog_read_loop()
		for {
			time.Sleep(10 * time.Second)
		}
	}
}
