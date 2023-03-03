package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/encoding/unicode"
)

// uint64 => string
func DecToHexstring(hex_num uint64) string {
	return strconv.FormatInt(int64(hex_num), 16)
}

// string => string
func BinstringToString(byteArr string) string {
	byteArr = strings.ReplaceAll(byteArr, ",", "")
	byteArr = strings.ReplaceAll(byteArr, "00", "")

	data, err := hex.DecodeString(byteArr)
	if err != nil {
		panic(err)
	}

	return string(data)
}

// string => []byte
func BinStringToByteArray(byteArr string) []byte {
	byteArr = strings.ReplaceAll(byteArr, ",", "")

	data, err := hex.DecodeString(byteArr)
	if err != nil {
		panic(err)
	}

	return data
}

// []byte => uint64
func ByteArrayToUint64(data []byte) uint64 {
	return binary.LittleEndian.Uint64(data)
}

// CompareInteger
func CompareDWord(regValue, fileValue string) bool {
	switch {
	case regValue == "0" && fileValue == "":
		fallthrough
	case regValue == fileValue:
		return true
	default:
		return false
	}
}

func ResizeByteArray(s []byte, size int) []byte {
	t := make([]byte, size)
	copy(t, s)
	return t
}

var utf16leEncoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
var utf16leDecoder = unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewDecoder()

func ConvertUtf8ToUtf16LE(message string) string {
	ut16LeEncodedMessage, err := utf16leEncoder.String(message)
	if err != nil {
		log.Println(err)
	}
	return ut16LeEncodedMessage
}

func ConvertUtf16LEToUtf8(message string) string {
	ut16LeEncodedMessage, err := utf16leDecoder.String(message)
	if err != nil {
		log.Println(err)
	}
	return ut16LeEncodedMessage
}

func UTF16PtrFromString(data string) *uint16 {
	value, err := syscall.UTF16PtrFromString(data)
	if err != nil {
		log.Println(err)
	}
	return value
}

func DecodeUTF16(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("must have even length byte slice")
	}

	u16s := make([]uint16, 1)
	ret := &bytes.Buffer{}
	b8buf := make([]byte, 4)

	lb := len(b)
	for i := 0; i < lb; i += 2 {
		u16s[0] = uint16(b[i]) + (uint16(b[i+1]) << 8)
		r := utf16.Decode(u16s)
		n := utf8.EncodeRune(b8buf, r[0])
		ret.Write(b8buf[:n])
	}

	return ret.String(), nil
}

func addComma(data string) string {
	var b strings.Builder
	for i := 0; i < len(data); i++ {
		if i != 0 && i%2 == 0 {
			b.WriteString(",")
		}
		b.WriteString(string(data[i]))
	}

	return b.String()
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
