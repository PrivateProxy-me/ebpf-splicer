package splicer

import (
	"net"
)

type fdWrapper struct {
	fd uint32
}

func (f *fdWrapper) control(fd uintptr) {
	f.fd = uint32(fd)
}

func getFd(c *net.TCPConn) (uint32, error) {
	wrapper := fdWrapper{}
	rawConn, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	err = rawConn.Control(wrapper.control)
	if err != nil {
		return 0, err
	}

	return wrapper.fd, nil
}
