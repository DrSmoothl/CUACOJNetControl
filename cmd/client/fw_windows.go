//go:build windows

package main

import (
	"cuacoj/netcontrol/pkg/fw"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

var fwOpMu sync.Mutex

// fwApply 接受 serverURL 与 dnsIPs，并按避免断线的顺序应用：
// 1) 临时将出站策略设为允许；2) 清理既有规则；3) 添加控制端、DNS、环回与白名单IP规则；4) 最后切换为出站阻断。
func fwApply(enabled bool, ips []net.IP, serverURL string, dnsIPs []net.IP) error {
	fwOpMu.Lock()
	defer fwOpMu.Unlock()
	debug := strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "1" || strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "true" || strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "yes"
	if debug {
		log.Printf("[FWAPPLY] begin enabled=%v ips=%d dns=%d url=%s", enabled, len(ips), len(dnsIPs), serverURL)
	}
	if err := fw.DisableDefaultBlock(); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWAPPLY] policy -> allowoutbound (reconfigure)")
	}
	if err := fw.ClearRules(); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWAPPLY] cleared old rules")
	}
	if !enabled {
		if debug {
			log.Printf("[FWAPPLY] disabled: keep allowoutbound")
		}
		return nil
	}
	if debug {
		log.Printf("[FWAPPLY] allow server by url")
	}
	allowServerByURL(serverURL)
	if debug {
		log.Printf("[FWAPPLY] allow DNS (%d)", len(dnsIPs))
	}
	if err := fw.AllowDNS(dnsIPs); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWAPPLY] allow loopback")
	}
	if err := fw.AllowLoopback(); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWAPPLY] allow whitelist IPs (%d)", len(ips))
	}
	if enabled && len(ips) == 0 && debug {
		log.Printf("[FWAPPLY] WARNING: 启用了控制但白名单域名解析得到 0 个 IP，将导致除控制端/DNS/环回外全部阻断。请检查 DNS 解析或域名配置。")
	}
	if err := fw.AllowIPs(ips); err != nil {
		return err
	}
	if err := fw.EnableDefaultBlock(); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWAPPLY] policy -> blockoutbound (active)")
		fw.ShowRules()
	}
	return nil
}

func fwClear() error {
	fwOpMu.Lock()
	defer fwOpMu.Unlock()
	debug := strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "1" || strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "true" || strings.ToLower(os.Getenv("NETCTRL_DEBUG")) == "yes"
	if debug {
		log.Printf("[FWCLEAR] start")
	}
	_ = fw.ClearRules()
	if err := fw.DisableDefaultBlock(); err != nil {
		return err
	}
	if debug {
		log.Printf("[FWCLEAR] policy -> allowoutbound done")
	}
	return nil
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
