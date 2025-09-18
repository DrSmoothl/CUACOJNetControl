//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ensureElevated relaunches the current executable with admin via UAC if not already elevated.
// It uses the presence of env NETCTRL_ELEVATED=1 as a loop guard.
func ensureElevated() {
	if os.Getenv("NETCTRL_ELEVATED") == "1" {
		return
	}
	// Try a simple privilege check by running a no-op that requires admin: net session
	// If it fails with access denied, elevate.
	chk := exec.Command("cmd", "/c", "net", "session")
	if err := chk.Run(); err == nil {
		return // already elevated
	}
	exe, _ := os.Executable()
	args := os.Args[1:]
	// rebuild arguments, add NETCTRL_ELEVATED=1 env
	env := append(os.Environ(), "NETCTRL_ELEVATED=1")
	// Use PowerShell Start-Process -Verb RunAs for reliability
	psArgs := []string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
		fmt.Sprintf("Start-Process -FilePath '%s' -ArgumentList '%s' -Verb RunAs", exe, strings.ReplaceAll(strings.Join(args, " "), "'", "''"))}
	cmd := exec.Command("powershell", psArgs...)
	cmd.Env = env
	_ = cmd.Start()
	os.Exit(0)
}
