package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/spddl/GoOffReg"
)

type Data struct {
	InfoHeader bool
	OpenHandle bool
	DelRootKey bool
	StringPath string
	RegPath    GoOffReg.ORHKEY
}

func GetClassification(value string) uint32 {
	switch {
	case value == "-":
		return GoOffReg.REG_NONE

	case strings.HasPrefix(value, `"`):
		return GoOffReg.REG_SZ

	case strings.HasPrefix(value, "hex:"):
		return GoOffReg.REG_BINARY

	case strings.HasPrefix(value, "dword:"):
		return GoOffReg.REG_DWORD

	case strings.HasPrefix(value, "hex(0):"):
		return GoOffReg.REG_NONE

	case strings.HasPrefix(value, "hex(1):"):
		return GoOffReg.REG_SZ

	case strings.HasPrefix(value, "hex(2):"):
		return GoOffReg.REG_EXPAND_SZ

	case strings.HasPrefix(value, "hex(3):"):
		return GoOffReg.REG_BINARY

	case strings.HasPrefix(value, "hex(4):"):
		return GoOffReg.REG_DWORD

	case strings.HasPrefix(value, "hex(5):"):
		return GoOffReg.REG_DWORD_BIG_ENDIAN

	case strings.HasPrefix(value, "hex(7):"):
		return GoOffReg.REG_MULTI_SZ

	case strings.HasPrefix(value, "hex(8):"):
		return GoOffReg.REG_RESOURCE_LIST

	case strings.HasPrefix(value, "hex(a):"):
		return GoOffReg.REG_RESOURCE_REQUIREMENTS_LIST

	case strings.HasPrefix(value, "hex(b):"):
		return GoOffReg.REG_QWORD
	}
	return 0
}

func SetClassification(key_type uint32, value string, data []byte) string {
	switch key_type {
	case 0: // REG_NONE
		return ""

	case 1: // REG_SZ
		return fmt.Sprintf("%q=%q", value, data)

	case 3: // REG_BINARY
		return fmt.Sprintf("%q=hex:%s", value, string(data)) // TODO: hex mit Komma

	case 4: // REG_DWORD
		if len(data) < 8 {
			data = ResizeByteArray(data, 8)
		}
		return fmt.Sprintf("%q=dword:%08d", value, ByteArrayToUint64(data))

	case 2: // REG_EXPAND_SZ
		fallthrough

	case 5: // REG_DWORD_BIG_ENDIAN
		fallthrough
	case 7: // REG_MULTI_SZ
		fallthrough
	case 8: // REG_RESOURCE_LIST
		hx := hex.EncodeToString(data) // TODO: vermutlich muss es immer eine gewissen Anzahl sein... also mit nil bytes auffüllen
		hx = addComma(hx)
		return fmt.Sprintf("%q=hex(%d):%s", value, key_type, hx) // TODO: hex mit Komma

	case 10: // REG_RESOURCE_REQUIREMENTS_LIST
		return value + "hex(a):" + string(data)

	case 11: // REG_QWORD
		return value + "hex(b):" + string(data)

	default:
		return ""
	}
}

func GetControlSet(orRootKey *GoOffReg.ORHKEY) string {
	var key_type uint32 = 0
	var lpDataLength uint32 = 4
	var lpData = make([]byte, lpDataLength)
	var lpSubKey = UTF16PtrFromString("Select")
	var lpValue = UTF16PtrFromString("Current")
	if result := GoOffReg.ORGetValue(*orRootKey, lpSubKey, lpValue, &key_type, &lpData[0], &lpDataLength); result == 0 {
		return fmt.Sprintf("ControlSet00%d", lpData[0])
	}
	return ""
}
