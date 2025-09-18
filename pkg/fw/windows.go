//go:build windows

package fw

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"log"
	"os"
)

// Strategy: default outbound = block; allow whitelist IPs via rules.
// Use rule prefix to manage lifecycle.

const rulePrefix = "CUACOJ-NETCTRL"

func isDebug() bool {
	v := strings.ToLower(os.Getenv("NETCTRL_DEBUG"))
	return v == "1" || v == "true" || v == "yes"
}

func run(args ...string) error {
	// Use powershell to ensure on Windows shell; but exec direct cmd is fine.
	cmd := exec.Command("netsh", append([]string{"advfirewall"}, args...)...)
	if isDebug() {
		log.Printf("[FW] netsh advfirewall %s", strings.Join(args, " "))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh error: %v, out=%s", err, string(out))
	}
	if isDebug() && len(out) > 0 {
		log.Printf("[FW] out: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func EnableDefaultBlock() error {
	return run("set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
}

func DisableDefaultBlock() error {
	// Restore default outbound=allow; inbound=block
	return run("set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")
}

func ClearRules() error {
	// delete existing rules with our prefix
	return run("firewall", "delete", "rule", fmt.Sprintf("name=%s", rulePrefix))
}

func AllowIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}
	// chunk into groups due to max command length
	const chunk = 50
	for i := 0; i < len(ips); i += chunk {
		j := i + chunk
		if j > len(ips) {
			j = len(ips)
		}
		list := make([]string, 0, j-i)
		for _, ip := range ips[i:j] {
			list = append(list, ip.String())
		}
		if err := run("firewall", "add", "rule",
			fmt.Sprintf("name=%s", rulePrefix),
			"dir=out", "action=allow", "protocol=any", fmt.Sprintf("remoteip=%s", strings.Join(list, ",")),
		); err != nil {
			return err
		}
	}
	return nil
}

// Allow DNS queries (udp/tcp 53) to any remote, otherwise domain resolution fails.
func AllowDNS() error {
	if err := run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
		"dir=out", "action=allow", "protocol=UDP", "remoteport=53"); err != nil {
		return err
	}
	if err := run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
		"dir=out", "action=allow", "protocol=TCP", "remoteport=53"); err != nil {
		return err
	}
	return nil
}

// Always allow loopback (localhost) connections to avoid breaking local IPC
func AllowLoopback() error {
	// allow both IPv4 and IPv6 loopback
	return run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
		"dir=out", "action=allow", "protocol=any", "remoteip=127.0.0.1,::1")
}

// Allow connection to control server (ws/wss)
func AllowServer(ip string, port int) error {
	if ip == "" || port <= 0 {
		return nil
	}
	if err := run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
		"dir=out", "action=allow", "protocol=TCP", fmt.Sprintf("remoteip=%s", ip), fmt.Sprintf("remoteport=%d", port)); err != nil {
		return err
	}
	return nil
}
