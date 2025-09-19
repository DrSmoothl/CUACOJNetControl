//go:build windows

package fw

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
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

// runCapture 与 run 类似但始终返回输出内容，用于调试展示当前规则。
func runCapture(args ...string) (string, error) {
	cmd := exec.Command("netsh", append([]string{"advfirewall"}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("netsh error: %v, out=%s", err, string(out))
	}
	return string(out), nil
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
	if err := run("firewall", "delete", "rule", fmt.Sprintf("name=%s", rulePrefix)); err != nil {
		// 当不存在匹配规则时，netsh 会返回非零退出码（例如“没有规则符合指定条件”），
		// 这不是致命错误，忽略以保证后续 EnableDefaultBlock/Allow* 能继续执行。
		if isDebug() {
			log.Printf("[FW] ClearRules ignore error: %v", err)
		}
		return nil
	}
	return nil
}

func AllowIPs(ips []net.IP) error {
	if len(ips) == 0 {
		if isDebug() {
			log.Printf("[FW] AllowIPs skipped: no IPs")
		}
		return nil
	}
	if isDebug() {
		log.Printf("[FW] AllowIPs applying %d IPs (TCP 80/443; optional UDP 443)", len(ips))
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
		// TCP 80
		if err := run("firewall", "add", "rule",
			fmt.Sprintf("name=%s", rulePrefix),
			"dir=out", "action=allow", "protocol=TCP", "remoteport=80", fmt.Sprintf("remoteip=%s", strings.Join(list, ",")),
		); err != nil {
			return err
		}
		// TCP 443
		if err := run("firewall", "add", "rule",
			fmt.Sprintf("name=%s", rulePrefix),
			"dir=out", "action=allow", "protocol=TCP", "remoteport=443", fmt.Sprintf("remoteip=%s", strings.Join(list, ",")),
		); err != nil {
			return err
		}
		// 可选：UDP 443（受 NETCTRL_ALLOW_UDP443 控制）
		if isDebug() || strings.ToLower(os.Getenv("NETCTRL_ALLOW_UDP443")) == "1" || strings.ToLower(os.Getenv("NETCTRL_ALLOW_UDP443")) == "true" {
			if err := run("firewall", "add", "rule",
				fmt.Sprintf("name=%s", rulePrefix),
				"dir=out", "action=allow", "protocol=UDP", "remoteport=443", fmt.Sprintf("remoteip=%s", strings.Join(list, ",")),
			); err != nil {
				return err
			}
		}
	}
	return nil
}

// AllowDNS 仅对指定 DNS 服务器 IP 放行 53 端口（UDP/TCP）。
func AllowDNS(servers []net.IP) error {
	if len(servers) == 0 {
		return fmt.Errorf("no DNS servers provided")
	}
	// 分片处理
	const chunk = 50
	for i := 0; i < len(servers); i += chunk {
		j := i + chunk
		if j > len(servers) {
			j = len(servers)
		}
		list := make([]string, 0, j-i)
		for _, ip := range servers[i:j] {
			list = append(list, ip.String())
		}
		if err := run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
			"dir=out", "action=allow", "protocol=UDP", "remoteport=53", fmt.Sprintf("remoteip=%s", strings.Join(list, ","))); err != nil {
			return err
		}
		if err := run("firewall", "add", "rule", fmt.Sprintf("name=%s", rulePrefix),
			"dir=out", "action=allow", "protocol=TCP", "remoteport=53", fmt.Sprintf("remoteip=%s", strings.Join(list, ","))); err != nil {
			return err
		}
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

// ShowRules 在调试模式下输出当前前缀相关的规则详情，帮助排查未创建 / 丢失的允许规则。
func ShowRules() {
	if !isDebug() {
		return
	}
	out, err := runCapture("firewall", "show", "rule", fmt.Sprintf("name=%s", rulePrefix))
	if err != nil {
		log.Printf("[FW] ShowRules error: %v", err)
		return
	}
	// 只输出前 2000 字符避免日志爆炸
	max := 2000
	if len(out) > max {
		log.Printf("[FW] rules (truncated)\n%s\n... (%d bytes truncated)", out[:max], len(out)-max)
	} else {
		log.Printf("[FW] rules\n%s", out)
	}
}
