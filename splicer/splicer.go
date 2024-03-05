package splicer

import (
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go copier copier.c

var objs copierObjects

func Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	if err := loadCopierObjects(&objs, nil); err != nil {
		return err
	}

	err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockets.FD(),
		Program: objs.BpfRedir,
		Attach:  ebpf.AttachSkSKBStreamParser,
		Flags:   0,
	})
	if err != nil {
		return err
	}
	err = link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  objs.Sockets.FD(),
		Program: objs.Verdict,
		Attach:  ebpf.AttachSkSKBStreamVerdict,
		Flags:   0,
	})
	if err != nil {
		return err
	}

	return nil
}

func Splice(src *net.TCPConn, dst *net.TCPConn, doneCh <-chan struct{}) (uint64, uint64, error) {
	defer src.Close()
	defer dst.Close()
	srcFd, err := getFd(src)
	if err != nil {
		return 0, 0, err
	}
	dstFd, err := getFd(dst)
	if err != nil {
		return 0, 0, err
	}
	srcSockKey := getSockKey(src)
	dstSockKey := getSockKey(dst)
	err = objs.Sockets.Update(srcSockKey, dstFd, ebpf.UpdateAny)
	if err != nil {
		return 0, 0, err
	}
	err = objs.Sockets.Update(dstSockKey, srcFd, ebpf.UpdateAny)
	if err != nil {
		objs.Sockets.Delete(srcSockKey)
		return 0, 0, nil
	}
	tmp := []byte{0}
	syscall.Recvmsg(int(srcFd), tmp, nil, syscall.MSG_PEEK)
	syscall.Recvmsg(int(dstFd), tmp, nil, syscall.MSG_PEEK)
	pollfd := []unix.PollFd{
		{
			Fd:      int32(srcFd),
			Events:  unix.POLLRDHUP,
			Revents: 0,
		},
		{
			Fd:      int32(dstFd),
			Events:  unix.POLLRDHUP,
			Revents: 0,
		},
	}
loop:
	for {
		select {
		case <-doneCh:
			break loop
		default:
			n, err := unix.Poll(pollfd, 3000)
			if n == 0 || (err != nil && err == syscall.EINTR) {
				continue
			} else {
				break loop
			}
		}
	}

	srcInfo, _ := unix.GetsockoptTCPInfo(int(srcFd), syscall.IPPROTO_TCP, syscall.TCP_INFO)
	dstInfo, _ := unix.GetsockoptTCPInfo(int(dstFd), syscall.IPPROTO_TCP, syscall.TCP_INFO)

	objs.Sockets.Delete(srcSockKey)
	objs.Sockets.Delete(dstSockKey)

	return dstInfo.Bytes_received, srcInfo.Bytes_received, nil
}

func Stop() {
	objs.Close()
}
