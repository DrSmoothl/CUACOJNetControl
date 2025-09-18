//go:build !windows

package main

import "net"

// Non-Windows stubs: no-op to satisfy builds and static analysis
func updateHosts(domToIPs map[string][]net.IP) error { return nil }
func clearHostsBlock() error                         { return nil }
