package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type Configuration struct {
	BlockingEnabled    bool                `json:"blocking_enabled"`
	EventlogMonitor    string              `json:"eventlog_monitor"`
	BlockStrings       []string            `json:"block_strings"`
	AllowStrings       []string            `json:"allow_strings"`
	RuleConfigurations []ConfigurationRule `json:"rule_configuration"`
}

type ConfigurationRule struct {
	RuleName    string `json:"rule_name"`
	ProgramPath string `json:"program_path"`
	RuleGUID    windows.GUID
}

// Reads configuration in its running directory
func ReadConfiguration() (Configuration, error) {
	var configuration Configuration
	var filebuffer []byte
	var err error

	running_directory, err := GetRunningDirectory()
	if err != nil {
		return Configuration{}, err
	}

	configurationPath := filepath.Join(running_directory, "configuration.json")
	filebuffer, err = os.ReadFile(configurationPath)
	if err != nil {
		return Configuration{}, err
	}

	err = json.Unmarshal(filebuffer, &configuration)
	if err != nil {
		return Configuration{}, err
	}

	// Replace template strings
	for index, item := range configuration.RuleConfigurations {
		configuration.RuleConfigurations[index].RuleGUID, _ = windows.GenerateGUID()
		if strings.Contains(item.ProgramPath, "$PROGRAMFILES86") {
			configuration.RuleConfigurations[index].ProgramPath = strings.Replace(item.ProgramPath, "$PROGRAMFILES86", PROGRAM_FILES_86, 1)
		} else if strings.Contains(item.ProgramPath, "$PROGRAMFILES") {
			configuration.RuleConfigurations[index].ProgramPath = strings.Replace(item.ProgramPath, "$PROGRAMFILES", PROGRAM_FILES, 1)
		}
	}

	prettyConfig, err := json.MarshalIndent(configuration, "", " ")
	eventlogger.Info(200, "Running configuration: \n"+string(prettyConfig[:]))

	return configuration, nil
}
