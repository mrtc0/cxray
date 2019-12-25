package utils

import (
	"bytes"
	"encoding/binary"
	"net"
	"os/user"
	"strconv"
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

// Uint2IPv4 is uint32 to ip address
// https://gist.github.com/ammario/649d4c0da650162efd404af23e25b86b
func Uint2IPv4(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, n)
	return ip
}

// Uint2Port is uint16 to port number string
// For example, 20480 → [0 80 0 0] → 80
func Uint2Port(n uint16) string {
	var port uint16

	b := make([]byte, 4)
	binary.LittleEndian.PutUint16(b, n)

	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.BigEndian, &port)
	return strconv.Itoa(int(port))
}
