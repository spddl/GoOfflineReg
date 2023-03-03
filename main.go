package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spddl/GoOffReg"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/text/encoding/unicode"
)

type FileData struct {
	Value string
	Key   string
	Type  uint32
}

const MAX_PATH = 256 // syscall.MAX_PATH

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	var orRootKey GoOffReg.ORHKEY
	lpHivePath := UTF16PtrFromString(RegFilePath)
	// https://learn.microsoft.com/en-us/windows/win32/devnotes/oropenhive
	result := GoOffReg.OROpenHive(lpHivePath, &orRootKey)
	if result != 0 || orRootKey == 0 {
		panic(fmt.Sprintf("OROpenHive failed: %d", result))
	}

	if ExportPath != "" {
		path := deleteRootKey(ExportPath, &orRootKey)
		keys := EnumKey(&orRootKey, path)

		for _, key := range keys {
			InfoHeader := false

			values := EnumValue(&orRootKey, path+"\\"+key)
			for _, value := range values {
				if ExportValue == "" || ExportValue == value {
					var key_type uint32 = 0
					var lpDataLength uint32 = MAX_PATH
					var lpData = make([]byte, MAX_PATH)
					var lpSubKey = UTF16PtrFromString(path + "\\" + key)
					var lpValue = UTF16PtrFromString(value)
					if result := GoOffReg.ORGetValue(orRootKey, lpSubKey, lpValue, &key_type, &lpData[0], &lpDataLength); result == 0 {
						if !InfoHeader {
							fmt.Printf("[%s\\%s]\n", ExportPath, key)
							InfoHeader = true
						}
						fmt.Println(SetClassification(key_type, value, UTF16toUTF8Array(lpData)))
					}
				}
			}
			if InfoHeader {
				fmt.Println()
			}
		}
	}

	if ExportServices {
		path := GetControlSet(&orRootKey) + `\Services`
		keys := EnumKey(&orRootKey, path)
		AvailableServices := make(map[string]string)

		for _, key := range keys {
			var valStart, valImagePath string
			for _, value := range EnumValue(&orRootKey, fmt.Sprintf("%s\\%s", path, key)) {
				if value == "Start" || value == "ImagePath" {
					var key_type uint32 = 0
					var lpDataLength uint32 = MAX_PATH
					if value == "Start" {
						lpDataLength = 4
					}
					var lpData = make([]byte, lpDataLength)
					var lpSubKey = UTF16PtrFromString(fmt.Sprintf("%s\\%s", path, key))
					var lpValue = UTF16PtrFromString(value)
					if result := GoOffReg.ORGetValue(orRootKey, lpSubKey, lpValue, &key_type, &lpData[0], &lpDataLength); result == 0 {
						if value == "Start" && key_type == 4 {
							valStart = fmt.Sprintf("%d", lpData[0])
						} else if value == "ImagePath" && key_type == 2 {
							valImagePath = ConvertUtf16LEToUtf8(string(lpData))
						}
					}
				}
			}

			if valStart != "" && GetExt(valImagePath) == "exe" {
				AvailableServices[strings.ToLower(key)] = valStart
			}
		}

		fmt.Printf("Windows Registry Editor Version 5.00\n\n")
		for service, start := range AvailableServices {
			fmt.Printf("[HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\%s]\n", service)
			fmt.Printf("\"Start\"=dword:0000000%s\n\n", start)
		}
	}

	for _, regfile := range ImportFilePath {
		file, err := os.Open(regfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer file.Close()
		var scanner *bufio.Scanner
		contentType := DetectContentType(file)
		fmt.Println("; Open", regfile, "("+contentType+")")
		file.Seek(0, 0)
		switch contentType {
		case "utf-8":
			scanner = bufio.NewScanner(file)
		case "utf-16le":
			dec := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()
			scanner = bufio.NewScanner(dec.Reader(file))
		default:
			file.Close()
			fmt.Fprintln(os.Stderr, "ContentType:", contentType)
			os.Exit(1)
		}

		var index uint
		var line string
		var WorkingRegPath = new(Data)
		for scanner.Scan() {
			index++
			if index == 1 {
				continue // skip "Windows Registry Editor Version"
			}

			if rawLine := scanner.Text(); len(rawLine) > 1 {
				// fmt.Printf("[%d] %s\n", index, rawLine)

				commentIndex := strings.Index(rawLine, ";")
				if commentIndex == 0 {
					rawLine = "" // remove comment Line
				}

				if strings.HasSuffix(rawLine, "\\") {
					line += strings.TrimSuffix(strings.TrimSpace(rawLine), "\\")
					continue
				}

				line += strings.TrimSpace(rawLine) // remove spaces
				if line == "" {
					continue // skip empty lines
				}

				if line[:1] == "[" {
					WorkingRegPath = new(Data)
					line = line[1 : len(line)-1]

					if line[0] == 45 { // [-HKEY_LOCAL_MACHINE\...
						WorkingRegPath.DelRootKey = true
						line = line[1:]
					}
					WorkingRegPath.StringPath = deleteRootKey(line, &orRootKey)

					if WorkingRegPath.OpenHandle {
						line = ""
						// https://learn.microsoft.com/en-us/windows/win32/devnotes/orclosekey
						GoOffReg.ORCloseKey(WorkingRegPath.RegPath)
					}

					err := OpenCreateKey(&orRootKey, WorkingRegPath)
					if err != nil {
						log.Println("// TODO:", line, "-", err)
						continue
					}

					line = ""
					if WorkingRegPath.DelRootKey { // Path has been deleted or does not exist
						continue
					}
					WorkingRegPath.OpenHandle = true

				} else {
					if !WorkingRegPath.OpenHandle {
						line = ""
						continue
					}

					equalPos := strings.Index(line, "=")
					fileData := FileData{
						Key:   strings.Trim(line[:equalPos], `"`),
						Value: line[equalPos+1:],
					}
					fileData.Type = GetClassification(fileData.Value)
					if fileData.Key == "@" {
						fileData.Key = ""
					}

					switch fileData.Type {
					case GoOffReg.REG_SZ:
						firstQuote := strings.IndexAny(fileData.Value, "\"")
						if firstQuote != 0 { // doesn't start with a "
							log.Println("Err? (firstQuote != 0)", rawLine)
						}
						secondQuote := strings.IndexAny(fileData.Value[firstQuote+1:], "\"")
						if secondQuote == -1 { // has no second "
							log.Println("Err? (secondQuote == -1)", rawLine)
						}
						commentIndex := strings.Index(fileData.Value[secondQuote+1:], ";")

						if commentIndex != -1 {
							fileData.Value = strings.TrimSpace(fileData.Value[:firstQuote+secondQuote+commentIndex+1])
						}

					default:
						commentIndex := strings.Index(fileData.Value, ";")
						if commentIndex != -1 {
							fileData.Value = strings.TrimSpace(fileData.Value[:commentIndex]) // remove comments
						}
					}

					switch fileData.Type {
					case GoOffReg.REG_NONE:
						var lpValue = UTF16PtrFromString(fileData.Key)
						GoOffReg.ORDeleteValue(WorkingRegPath.RegPath, lpValue)

					case GoOffReg.REG_SZ:
						fileData.Value = strings.ReplaceAll(fileData.Value, `\"`, `"`)
						fileData.Value = strings.ReplaceAll(fileData.Value, `\\`, `\`)
						if fileData.Value[0] == 34 && fileData.Value[len(fileData.Value)-1] == 34 {
							fileData.Value = fileData.Value[1 : len(fileData.Value)-1]
						}

						var lpValue = UTF16PtrFromString(fileData.Key)
						if fileData.Value == "" {
							GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, nil, 0)
						} else {
							lpData := []byte(ConvertUtf8ToUtf16LE(fileData.Value))
							var lpDataLength = uint32(len(lpData))
							if lpDataLength == 0 {
								lpData = nil
							}
							GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, &lpData[0], lpDataLength)
						}

					case GoOffReg.REG_DWORD:
						var RegFileValue = fileData.Value[6:] // deletes the "dword:"

						// Hex => Dec
						decimal, err := strconv.ParseUint(RegFileValue, 16, 32)
						if err != nil {
							log.Println(err)
						}

						// Dec => BinLE
						var lpData = make([]byte, 4)
						binary.LittleEndian.PutUint32(lpData, uint32(decimal))

						var lpValue = UTF16PtrFromString(fileData.Key)
						GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, &lpData[0], uint32(len(lpData)))

					case registry.EXPAND_SZ: // REG_EXPAND_SZ
						var RegFileValue = BinstringToString(fileData.Value[7:])
						var lpValue = UTF16PtrFromString(fileData.Key)
						var lpData = []byte(ConvertUtf8ToUtf16LE(RegFileValue))
						if len(lpData) < 2 {
							lpData = ResizeByteArray(lpData, 2)
						}
						GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, &lpData[0], uint32(len(lpData)))

					case GoOffReg.REG_BINARY: // Binary data (hex: / hex(3):)
						lpData, err := hex.DecodeString(strings.ReplaceAll(fileData.Value[strings.Index(fileData.Value, ":")+1:], ",", ""))
						if err != nil {
							WorkingRegPath.Log(ErrLvl, line+" ("+err.Error()+")") // Entry not in the same format
							line = ""
							continue
						}
						var lpValue = UTF16PtrFromString(fileData.Key)
						GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, &lpData[0], uint32(len(lpData)))

					case GoOffReg.REG_QWORD: // QWORD
						fallthrough
					case GoOffReg.REG_MULTI_SZ: // MULTI_SZ
						var lpValue = UTF16PtrFromString(fileData.Key)
						var lpData = BinStringToByteArray(fileData.Value[7:])

						GoOffReg.ORSetValue(WorkingRegPath.RegPath, lpValue, fileData.Type, &lpData[0], uint32(len(lpData)))

					default:
						log.Printf("// TODO: unknown typ: %#v\n", fileData)
						continue
					}

					line = ""
				}
			} else {
				line = ""
			}
		}

		if err := scanner.Err(); err != nil {
			fmt.Printf("Invalid input: %s\n", err)
		}
	}

	if Commit {
		tempFile := os.Getenv("TEMP") + "\\" + RandStringBytes(6)
		for {
			if _, err := os.Stat(tempFile); errors.Is(err, os.ErrNotExist) {
				break
			}
			tempFile = os.Getenv("TEMP") + "\\" + RandStringBytes(6)
		}

		lpHiveNewPath := UTF16PtrFromString(tempFile)
		major, minor := GoOffReg.GetWindowsVersion()
		if major == 6 && minor == 2 {
			minor = 1
		}

		if result = GoOffReg.ORSaveHive(orRootKey, lpHiveNewPath, major, minor); result != 0 {
			log.Println("ORSaveHive", result)
		}

		if err := os.Rename(RegFilePath, RegFilePath+".old"); err != nil {
			log.Println(err)
		}

		if result = GoOffReg.ORCloseHive(orRootKey); result != 0 {
			log.Println("ORCloseHive", result)
		}

		if err := Copy(tempFile, RegFilePath); err != nil {
			log.Fatal(err)
		}

		if err := os.Remove(tempFile); err != nil {
			log.Println(err)
		}

		if err := os.Remove(RegFilePath + ".old"); err != nil {
			log.Println(err)
		}
	} else {
		if result = GoOffReg.ORCloseHive(orRootKey); result != 0 {
			log.Println("ORCloseHive", result)
		}
	}
}

func DetectContentType(file *os.File) string {
	buffer := make([]byte, 512)
	n, err := file.Read(buffer)
	if err != nil {
		log.Println("Error:", err)
		os.Exit(1)
	}
	contentType := http.DetectContentType(buffer[:n])
	index := strings.Index(contentType, "; charset=")
	if index == -1 {
		return ""
	}
	return contentType[index+10:]
}

func deleteRootKey(path string, orRootKey *GoOffReg.ORHKEY) string {
	temp := strings.ToUpper(path)
	switch {
	case strings.HasPrefix(temp, "HKEY_CURRENT_CONFIG\\"):
		return path[20:]
	case strings.HasPrefix(temp, "HKEY_CURRENT_USER\\"):
		return path[18:]
	case strings.HasPrefix(temp, "HKEY_LOCAL_MACHINE\\SAM\\"):
		return path[23:]
	case strings.HasPrefix(temp, "HKEY_LOCAL_MACHINE\\BCD00000000\\"):
		return path[31:]
	case strings.HasPrefix(temp, "HKEY_LOCAL_MACHINE\\SECURITY\\"):
		return path[28:]
	case strings.HasPrefix(temp, "HKEY_LOCAL_MACHINE\\SOFTWARE\\"):
		return path[28:]
	case strings.HasPrefix(temp, "HKEY_LOCAL_MACHINE\\SYSTEM\\"):
		if i := strings.Index(temp, "CURRENTCONTROLSET"); i != -1 {
			return GetControlSet(orRootKey) + path[i+17:]
		}
		return path[26:]
	case strings.HasPrefix(temp, "HKEY_USERS\\.DEFAULT\\"):
		return path[20:]
	default:
		return path
	}
}

func OpenCreateKey(orRootKey *GoOffReg.ORHKEY, workingRegPath *Data) error {
	if workingRegPath.StringPath == "" {
		return errors.New("OROpenKey: StringPath is empty")
	}
	stringPath := UTF16PtrFromString(workingRegPath.StringPath)
	for {
		switch result := GoOffReg.OROpenKey(*orRootKey, stringPath, &workingRegPath.RegPath); result {
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d
		case 0:
			// ERROR_SUCCESS
			if workingRegPath.DelRootKey { // Path exists
				switch result := GoOffReg.ORDeleteKey(*orRootKey, stringPath); result {
				case 2: // ERROR_FILE_NOT_FOUND
					log.Println(result, "ERROR_FILE_NOT_FOUND", workingRegPath.StringPath)
				case 87: // ERROR_INVALID_PARAMETER
					log.Println(result, "ERROR_INVALID_PARAMETER", workingRegPath.StringPath)
				case 1020: // ERROR_KEY_HAS_CHILDREN
					for _, subKey := range EnumKey(orRootKey, workingRegPath.StringPath) {
						WorkingSubRegPath := Data{StringPath: workingRegPath.StringPath + "\\" + subKey, DelRootKey: true}
						err := OpenCreateKey(orRootKey, &WorkingSubRegPath)
						if err != nil {
							log.Println(err)
						}
					}
					OpenCreateKey(orRootKey, workingRegPath)
				}
			}
			return nil
		case 2: // ERROR_FILE_NOT_FOUND
			if workingRegPath.DelRootKey {
				// Key does not exist and will not be created
				return nil
			}
			if result := GoOffReg.ORCreateKey(*orRootKey, stringPath, nil, 0, nil, &workingRegPath.RegPath, nil); result != 0 {
				workingRegPath.StringPath = removeLastSlash(workingRegPath.StringPath)
				OpenCreateKey(orRootKey, workingRegPath)
			}
			continue
		default:
			log.Println("result:", result)
			return fmt.Errorf("OROpenKey: %d", result)
		}
	}
}

func removeLastSlash(line string) string {
	i := strings.LastIndex(line, "\\")
	if i == -1 {
		return ""
	}
	return line[:i]
}

func Copy(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	if err != nil {
		return err
	}
	return out.Close()
}

func EnumKey(orRootKey *GoOffReg.ORHKEY, exportPath string) []string {
	var resultArray = []string{}
	WorkingRegPath := Data{StringPath: exportPath}
	err := OpenCreateKey(orRootKey, &WorkingRegPath)
	if err != nil {
		log.Println(err)
	}

	lpDataLength := uint32(MAX_PATH)
	var lpData = make([]byte, lpDataLength)
	for i := uint32(0); ; i++ {
		switch result := GoOffReg.OREnumKey(WorkingRegPath.RegPath, i, &lpData[0], &lpDataLength, nil, nil, nil); result {
		case 0: // ERROR_SUCCESS
			resultArray = append(resultArray, string(UTF16toUTF8Array(lpData)[:lpDataLength]))

			lpDataLength = uint32(MAX_PATH)
			lpData = make([]byte, lpDataLength)

		case 234: // ERROR_MORE_DATA
			lpDataLength = uint32(lpDataLength * 2)
			lpData = make([]byte, lpDataLength)

		case 259: // ERROR_NO_MORE_ITEMS
			return resultArray
		}
	}
}

func EnumValue(orRootKey *GoOffReg.ORHKEY, exportPath string) []string {
	var resultArray = []string{}
	WorkingRegPath := Data{StringPath: exportPath}
	err := OpenCreateKey(orRootKey, &WorkingRegPath)
	if err != nil {
		log.Println(err)
	}

	lpDataLength := uint32(MAX_PATH)
	for i := uint32(0); ; i++ {
		var lpData = make([]byte, lpDataLength)
		result := GoOffReg.OREnumValue(WorkingRegPath.RegPath, i, &lpData[0], &lpDataLength, nil, nil, nil)
		switch result {
		case 0: // ERROR_SUCCESS
			resultArray = append(resultArray, string(UTF16toUTF8Array(lpData)[:lpDataLength]))
			lpDataLength = uint32(MAX_PATH)

		case 234: // ERROR_MORE_DATA
			lpDataLength = uint32(lpDataLength * 2)
			continue

		case 259: // ERROR_NO_MORE_ITEMS
			return resultArray
		}
	}
}

func UTF16toUTF8Array(data []byte) []byte {
	result := []byte{}
	for i := 0; i < len(data); i += 2 {
		if data[i] != 0 {
			result = append(result, data[i])
		} else {
			return result
		}
	}
	return result
}
