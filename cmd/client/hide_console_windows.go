//go:build windows

package main

import (
	"os"
	"syscall"
)

// hideConsole attempts to hide the current console window (if any) on Windows.
// It is a no-op if NETCTRL_SHOW_CONSOLE 环境变量被设置 (非空值)。
func hideConsole() {
	if os.Getenv("NETCTRL_SHOW_CONSOLE") != "" { // allow debug
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	user32 := syscall.NewLazyDLL("user32.dll")
	showWindow := user32.NewProc("ShowWindow")
	const SW_HIDE = 0
	// Get window handle
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 { // already no console (service mode?)
		return
	}
	// Hide window
	showWindow.Call(hwnd, uintptr(SW_HIDE))
}

// ensureConsoleHidden is called early from main (after logging init) to hide quickly.
func ensureConsoleHidden() { hideConsole() }

// Optional helper to re-show console if needed (not used currently)
func showConsole() {
	if os.Getenv("NETCTRL_SHOW_CONSOLE") == "" { // only if explicitly allowed we would show, so skip
		return
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleWindow := kernel32.NewProc("GetConsoleWindow")
	user32 := syscall.NewLazyDLL("user32.dll")
	showWindow := user32.NewProc("ShowWindow")
	const SW_SHOW = 5
	hwnd, _, _ := getConsoleWindow.Call()
	if hwnd == 0 {
		return
	}
	showWindow.Call(hwnd, uintptr(SW_SHOW))
}
