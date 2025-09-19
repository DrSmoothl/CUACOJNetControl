//go:build windows

package main

import (
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

// ensureElevated relaunches the current executable with admin via UAC if not already elevated.
// It uses the presence of env NETCTRL_ELEVATED=1 as a loop guard.
// Windows API & constants
const (
	tokenElevation = 20
)

var (
	modadvapi32             = syscall.NewLazyDLL("advapi32.dll")
	procGetTokenInformation = modadvapi32.NewProc("GetTokenInformation")
	modshell32              = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW       = modshell32.NewProc("ShellExecuteW")
)

func isElevated() bool {
	var h syscall.Token
	ph, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	if err := syscall.OpenProcessToken(ph, syscall.TOKEN_QUERY, &h); err != nil {
		return false
	}
	defer h.Close()
	var out uint32
	var retLen uint32
	// TOKEN_ELEVATION is a struct with a single DWORD (uint32)
	r1, _, _ := procGetTokenInformation.Call(uintptr(h), uintptr(tokenElevation), uintptr(unsafe.Pointer(&out)), uintptr(4), uintptr(unsafe.Pointer(&retLen)))
	if r1 == 0 {
		return false
	}
	return out != 0
}

func shellRunAs() error {
	exe, _ := os.Executable()
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	paramsStr := ""
	// propagate args
	if len(os.Args) > 1 {
		// simple join with quoting for spaces
		for _, a := range os.Args[1:] {
			if strings.ContainsAny(a, " \t\"") {
				a = "\"" + strings.ReplaceAll(a, "\"", "\\\"") + "\""
			}
			if paramsStr != "" {
				paramsStr += " "
			}
			paramsStr += a
		}
	}
	params, _ := syscall.UTF16PtrFromString(paramsStr)
	show := 1 // SW_SHOWNORMAL
	r1, _, err := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(file)), uintptr(unsafe.Pointer(params)), 0, uintptr(show))
	// per docs: >32 success
	if r1 <= 32 {
		return err
	}
	return nil
}

func ensureElevated() {
	if isElevated() {
		return
	}
	if os.Getenv("NETCTRL_ELEVATED") == "1" {
		return
	}
	// mark to avoid infinite loop in case user cancels UAC
	_ = os.Setenv("NETCTRL_ELEVATED", "1")
	if err := shellRunAs(); err != nil {
		log.Printf("[ELEVATE] ShellExecuteW runas failed: %v", err)
		return // continue non-elevated (some features will fail)
	}
	os.Exit(0)
}
