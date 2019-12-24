package utils

import (
	"bytes"
	"os/user"
)

// TrimNullByte is trim null byte (0x00) from []byte
func TrimNullByte(b []byte) []byte {
	return bytes.Trim(b, "\x00")
}

// GetUsernameByUID is return username lookup by uid
func GetUsernameByUID(uid string) string {
	u, err := user.LookupId(uid)
	if err != nil {
		return "unknown"
	}
	return u.Username
}
