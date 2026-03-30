package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/google/winops/winlog"
)

var PROGRAM_FILES_86 = os.Getenv("programfiles(x86)")
var PROGRAM_FILES = os.Getenv("programfiles")

func CreateEventlogQuery(querystring map[string]string) (*uint16, error) {
	xmlQuery, err := winlog.BuildStructuredXMLQuery(querystring)
	if err != nil {
		return nil, err
	}
	query, err := syscall.UTF16PtrFromString(string(xmlQuery))
	if err != nil {
		return nil, err
	}

	return query, nil
}

func GetRunningDirectory() (string, error) {
	executablePath, err := os.Executable()
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("os.Executable(): %v", err))
		return "", err
	}

	// Should never happen but let's be safe :)
	executablePath, err = filepath.EvalSymlinks(executablePath)
	if err != nil {
		eventlogger.Error(200, fmt.Sprintf("filepath.EvalSymlinks(): %v", err))
		return "", err
	}
	return filepath.Dir(executablePath), nil
}

func CreateLogFile() (*os.File, error) {
	tempDir := os.TempDir()
	monitorFileName := filepath.Join(tempDir, "umbrellamonitor.log")
	_ = os.Rename(monitorFileName, monitorFileName+".1")

	logfile, err := os.OpenFile(monitorFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}

	return logfile, err
}
