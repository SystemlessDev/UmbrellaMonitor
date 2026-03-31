# UmbrellaMonitor

UmbrellaMonitor tries to prevent the user from bypassing Cisco Umbrella's protection.

During a network interface toggle, Umbrella's protection will be temporarily disabled. This program allows you to disable internet access for specific applications during situations where the protection is disabled.

## Usage

Put the UmbrellaMonitor executable in a folder together with a configuration.json file. Make sure the user cannot modify either file, as that would make it possible to disable the program.

You can run UmbrellaMonitor both as a service or standalone in your own ways. It is recommended to use it as a service.

### Example command to create service

```
sc.exe create umbrellamonitor binPath=C:\IT_DEPARTMENT\umbrellamonitor.exe start=auto
```

### Example configuration.json
```json
{
    "blocking_enabled": true,
    "eventlog_monitor": "Cisco Secure Client - Umbrella",
    "block_string": "IPv4 DNS redirection: DEACTIVATED",
    "allow_string": "IPv4 DNS redirection: ACTIVATED",
    "rule_configuration": [
        {
            "rule_name": "Block_Google_Chrome",
            "program_path": "$PROGRAMFILES\\Google\\Chrome\\Application\\chrome.exe"
        },
        {
            "rule_name": "Block_MS_Edge",
            "program_path": "$PROGRAMFILES86\\Microsoft\\Edge\\Application\\msedge.exe"
        },
        {
            "rule_name": "Block_Firefox",
            "program_path": "$PROGRAMFILES\\Mozilla Firefox\\firefox.exe"
        }
    ]
}
```

The template strings $PROGRAMFILES and $PROGRAMFILES86 will use the system environment variable for the respectable path.
