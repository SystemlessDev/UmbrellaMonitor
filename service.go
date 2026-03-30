package main

import (
	"golang.org/x/sys/windows/svc"
)

type umbrellaService struct{}

func (m *umbrellaService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	go eventlog_read_loop()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	eventlogger.Info(200, "Service started")
loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			default:
				// Ignore
			}
		}
	}

	changes <- svc.Status{State: svc.StopPending}
	return
}
