package main

import (
	"fmt"
)

type LogLevel int

const (
	InfoLvl LogLevel = iota
	WarnLvl
	ErrLvl
	PanicLvl
)

func (d *Data) LogInfoHeader() {
	if !d.InfoHeader {
		d.InfoHeader = true
		fmt.Printf(NoColor, "\n["+d.StringPath+"]")
	}
}

func (d *Data) Log(level LogLevel, line string) {
	switch level {
	case InfoLvl:
		if !NoInfo {
			d.LogInfoHeader()
			fmt.Printf(InfoColor, line)
		}
	case WarnLvl:
		if !NoWarn {
			d.LogInfoHeader()
			fmt.Printf(WarningColor, line)
		}
	case ErrLvl:
		if !NoErr {
			d.LogInfoHeader()
			fmt.Printf(ErrorColor, line)
		}
	case PanicLvl:
		d.LogInfoHeader()
		fmt.Printf(PanicColor, line)
	}
}
