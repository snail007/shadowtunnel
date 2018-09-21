// +build !linux

package redir

import (
	"net"
)

func RealServerAddress(conn *net.Conn) (string, error) {
	panic("redir not supported by your OS")
	return "", nil
}
