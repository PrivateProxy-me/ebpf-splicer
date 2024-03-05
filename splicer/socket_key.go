package splicer

import "net"

func getSockKey(c *net.TCPConn) [12]byte {
	res := [12]byte{}
	sip := c.LocalAddr().(*net.TCPAddr)
	for i := 0; i < 4; i++ {
		res[i] = sip.IP[i]
	}
	dip := c.RemoteAddr().(*net.TCPAddr)
	for i := 0; i < 4; i++ {
		res[i+4] = dip.IP[i]
	}
	res[8] = byte(sip.Port & 0xFF)
	res[9] = byte((sip.Port >> 8) & 0xFF)
	res[10] = byte(dip.Port >> 8)
	res[11] = byte(dip.Port & 0xFF)
	return res
}
