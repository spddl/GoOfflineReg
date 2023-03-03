package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	NoInfo         bool
	NoWarn         bool
	NoErr          bool
	Commit         bool
	ExportServices bool
	RegFilePath    string
	ImportFilePath []string
	ExportPath     string
	ExportValue    string
)

const (
	NoColor      = "%s\n"
	InfoColor    = "\033[1;32m%s\033[0m\n"
	WarningColor = "\033[1;33m%s\033[0m\n"
	ErrorColor   = "\033[1;31m%s\033[0m\n"
	PanicColor   = "\033[1;35m%s\033[0m\n"
)

func init() {
	flag.BoolVar(&NoInfo, "noinfo", false, "Without info")
	flag.BoolVar(&NoWarn, "nowarn", false, "Without warning")
	flag.BoolVar(&NoErr, "noerr", false, "Without error")

	flag.BoolVar(&Commit, "commit", false, "")
	flag.BoolVar(&ExportServices, "exportservices", false, "")
	flag.StringVar(&RegFilePath, "path", "", "absolut path")
	im := flag.String("import", "", "import regFiles")
	flag.StringVar(&ExportPath, "exportpath", "", "")
	flag.StringVar(&ExportValue, "exportvalue", "", "")
	flag.Parse()
	if *im != "" {
		ImportFilePath = strings.Split(*im, ",")
	}

	if RegFilePath == "" || ((len(ImportFilePath) == 0 && ExportPath == "") && !ExportServices) {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if _, err := os.Stat(RegFilePath); errors.Is(err, os.ErrNotExist) {
		panic(fmt.Sprintf("%s does not exist", RegFilePath))
	}
	if len(ImportFilePath) != 0 {
		for _, importFile := range ImportFilePath {
			if _, err := os.Stat(importFile); errors.Is(err, os.ErrNotExist) {
				panic(fmt.Sprintf("%s does not exist", importFile))
			}
		}
	}
}
