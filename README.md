# UmbrellaMonitor

This is a small utility that monitors the current status of Cisco Umbrella, and blocks the firewall if it disconnects. 

## Why does this exist

Umbrella does not have a killswitch, and therefore it can be bypassed by disconnecting and reconnecting the network interface.
As in, you can toggle flight mode and bypass it...

This small tool just blocks the browser from accessing the internet while this is possible.
