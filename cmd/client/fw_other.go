//go:build !windows

package main

import "net"

func fwApply(enabled bool, ips []net.IP) error { return nil }
func fwClear() error                           { return nil }
func allowServerByURL(serverURL string)        {}
