//go:build android

package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// configureDialerProtection asks the host Android VpnService to keep every
// MorokSS tunnel socket outside the TUN interface. Without this the transport
// would connect back into its own VPN and loop forever.
func configureDialerProtection(dialer *net.Dialer, path string) {
	if path == "" {
		return
	}
	dialer.ControlContext = func(_ context.Context, _, _ string, raw syscall.RawConn) error {
		var protectErr error
		if err := raw.Control(func(fd uintptr) {
			protectErr = protectAndroidSocket(path, int(fd))
		}); err != nil {
			return fmt.Errorf("access tunnel socket: %w", err)
		}
		return protectErr
	}
}

func protectAndroidSocket(path string, fd int) error {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fmt.Errorf("connect to VpnService protect socket: %w", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))

	if _, _, err = connection.WriteMsgUnix([]byte{1}, syscall.UnixRights(fd), nil); err != nil {
		return fmt.Errorf("send tunnel socket to VpnService: %w", err)
	}
	response := []byte{1}
	if _, err = connection.Read(response); err != nil {
		return fmt.Errorf("read VpnService protection result: %w", err)
	}
	if response[0] != 0 {
		return fmt.Errorf("VpnService rejected tunnel socket")
	}
	return nil
}
