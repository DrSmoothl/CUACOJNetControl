//go:build windows

package main

import (
	"cuacoj/netcontrol/pkg/fw"
	"net"
	"net/url"
	"strings"
)

func fwApply(enabled bool, ips []net.IP) error {
	// Clear old rules then apply
	if err := fw.ClearRules(); err != nil {
		return err
	}
	if !enabled {
		return fw.DisableDefaultBlock()
	}
	if err := fw.EnableDefaultBlock(); err != nil {
		return err
	}
	// always allow DNS resolution and loopback IPC
	if err := fw.AllowDNS(); err != nil {
		return err
	}
	if err := fw.AllowLoopback(); err != nil {
		return err
	}
	if err := fw.AllowIPs(ips); err != nil {
		return err
	}
	return nil
}

func fwClear() error {
	_ = fw.ClearRules()
	return fw.DisableDefaultBlock()
}

// helper to allow server url (ws://host:port or wss://)
func allowServerByURL(serverURL string) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return
	}
	host := u.Host
	if strings.Contains(host, ":") {
		parts := strings.Split(host, ":")
		host = parts[0]
	}
	ips, _ := net.LookupIP(host)
	port := 80
	if u.Scheme == "wss" {
		port = 443
	}
	if u.Port() != "" {
		if p, _ := net.LookupPort("tcp", u.Port()); p > 0 {
			port = p
		}
	}
	for _, ip := range ips {
		_ = fw.AllowServer(ip.String(), port)
	}
}
