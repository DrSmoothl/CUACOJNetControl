//go:build windows

package proxy

import (
	"log"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

// WinInet options (partial)
const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

var (
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

func internetSetOption(option uintptr) {
	// BOOL InternetSetOptionW(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
	// We ignore return value; failures are non-fatal for our scenario.
	_, _, _ = procInternetSetOptionW.Call(0, option, 0, 0)
}

// EnableSystemProxy 通过修改 HKCU WinINET 注册表并广播设置变化来启用系统代理。
// addr 形如 127.0.0.1:8888
func EnableSystemProxy(addr string) error {
	if addr == "" {
		return nil
	}
	// ProxyServer 推荐写成 http=...;https=...
	hostPort := addr
	if !strings.Contains(hostPort, ":") {
		hostPort += ":80"
	}
	proxyValue := "http=" + hostPort + ";https=" + hostPort
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		log.Printf("[SYSPROXY] open reg error: %v", err)
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		log.Printf("[SYSPROXY] set ProxyEnable error: %v", err)
		return err
	}
	if err := k.SetStringValue("ProxyServer", proxyValue); err != nil {
		log.Printf("[SYSPROXY] set ProxyServer error: %v", err)
		return err
	}
	// 可选：保留本地域名直连
	_ = k.SetStringValue("ProxyOverride", "<local>")
	// 通知 WinINET 设置已变
	internetSetOption(internetOptionSettingsChanged)
	internetSetOption(internetOptionRefresh)
	log.Printf("[SYSPROXY] enabled WinINET proxy=%s", proxyValue)
	return nil
}

// DisableSystemProxy 关闭并清理设置。
func DisableSystemProxy() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings`, registry.SET_VALUE)
	if err != nil {
		log.Printf("[SYSPROXY] open reg error: %v", err)
		return err
	}
	defer k.Close()
	if err := k.SetDWordValue("ProxyEnable", 0); err != nil {
		log.Printf("[SYSPROXY] disable set ProxyEnable error: %v", err)
		return err
	}
	// 不强制清空 ProxyServer，保留用户原值风险：若要真正还原，可在启用前读取备份。这里简单清空。
	_ = k.SetStringValue("ProxyServer", "")
	internetSetOption(internetOptionSettingsChanged)
	internetSetOption(internetOptionRefresh)
	log.Printf("[SYSPROXY] disabled WinINET proxy")
	return nil
}

// （可选）若未来需要备份还原，可添加结构保存原始 ProxyEnable/ProxyServer。

// 防止被 GC（在少数旧系统）提前回收
var _ unsafe.Pointer
