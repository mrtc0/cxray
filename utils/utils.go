package utils

import "bytes"

func TrimNullByte(b []byte) []byte {
	return bytes.Trim(b, "\x00")
}
