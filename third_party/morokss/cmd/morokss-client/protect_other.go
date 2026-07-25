//go:build !android

package main

import "net"

func configureDialerProtection(_ *net.Dialer, _ string) {}
