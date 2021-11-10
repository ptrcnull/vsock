//+build linux

package vsock

import (
	"fmt"
	"golang.org/x/sys/unix"
)

// newConn creates a Conn using a connFD, immediately setting the connFD to
// non-blocking mode for use with the runtime network poller.
func newConn(cfd connFD, local, remote *Addr) (*Conn, error) {
	// Note: if any calls fail after this point, cfd.Close should be invoked
	// for cleanup because the socket is now non-blocking.
	if err := cfd.SetNonblocking(local.fileName()); err != nil {
		return nil, err
	}

	return &Conn{
		fd:     cfd,
		local:  local,
		remote: remote,
	}, nil
}

// dial is the entry point for Dial on Linux.
func dial(cid, port uint32) (*Conn, error) {
	cfd, err := newConnFD()
	if err != nil {
		return nil, err
	}

	return dialLinux(cfd, cid, port)
}

func getLocalContextID() (uint32, error) {
	fd, err := unix.Open("/dev/vsock", 0660, unix.O_RDONLY)
	if err != nil {
		return 0, fmt.Errorf("open vsock: %w", err)
	}
	defer unix.Close(fd)

	res, err := unix.IoctlGetInt(fd, unix.IOCTL_VM_SOCKETS_GET_LOCAL_CID)
	if err != nil {
		return 0, fmt.Errorf("ioctl get: %w", err)
	}

	return uint32(res), nil
}

// dialLinux is the entry point for tests on Linux.
func dialLinux(cfd connFD, cid, port uint32) (c *Conn, err error) {
	defer func() {
		if err != nil {
			// If any system calls fail during setup, the socket must be closed
			// to avoid file descriptor leaks.
			_ = cfd.EarlyClose()
		}
	}()

	lcid, err := getLocalContextID()
	if err != nil {
		return nil, err
	}

	lsa := &unix.SockaddrVM{
		CID:  lcid,
		Port: 0x03ff,
	}

	if err := cfd.Bind(lsa); err != nil {
		return nil, err
	}

	rsa := &unix.SockaddrVM{
		CID:  cid,
		Port: port,
	}

	if err := cfd.Connect(rsa); err != nil {
		return nil, err
	}

	local := &Addr{
		ContextID: lsa.CID,
		Port:      lsa.Port,
	}

	remote := &Addr{
		ContextID: cid,
		Port:      port,
	}

	return newConn(cfd, local, remote)
}
