package main

import (
	"log"
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
		log.Println("os.Executable(): \n", err)
		return "", err
	}

	// Should never happen but let's be safe :)
	executablePath, err = filepath.EvalSymlinks(executablePath)
	if err != nil {
		log.Println("filepath.EvalSymlinks(): \n", err)
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
