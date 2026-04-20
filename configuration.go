package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type Configuration struct {
	EventlogMonitor    string              `json:"eventlog_monitor"`
	BlockStringV4      string              `json:"block_string_v4"`
	AllowStringV4      string              `json:"allow_string_v4"`
	BlockStringV6      string              `json:"block_string_v6"`
	AllowStringV6      string              `json:"allow_string_v6"`
	RuleConfigurations []ConfigurationRule `json:"rule_configuration"`
}

type ConfigurationRule struct {
	RuleName    string `json:"rule_name"`
	ProgramPath string `json:"program_path"`
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
