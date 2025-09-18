//go:build windows

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	hostsPath  = `C:\\Windows\\System32\\drivers\\etc\\hosts`
	hostsBegin = "# BEGIN CUACOJ-NETCTRL"
	hostsEnd   = "# END CUACOJ-NETCTRL"
)

// updateHosts replaces our managed block with provided domain->IPs mappings.
func updateHosts(domToIPs map[string][]net.IP) error {
	// read existing
	content := ""
	if b, err := os.ReadFile(hostsPath); err == nil {
		content = string(b)
	}
	lines := []string{}
	if content != "" {
		scanner := bufio.NewScanner(strings.NewReader(content))
		inBlock := false
		for scanner.Scan() {
			line := scanner.Text()
			if strings.TrimSpace(line) == hostsBegin {
				inBlock = true
				continue
			}
			if strings.TrimSpace(line) == hostsEnd {
				inBlock = false
				continue
			}
			if !inBlock {
				lines = append(lines, line)
			}
		}
	}
	// build new block
	block := []string{hostsBegin}
	for d, ips := range domToIPs {
		for _, ip := range ips {
			// one entry per ip
			block = append(block, fmt.Sprintf("%s %s", ip.String(), d))
		}
	}
	block = append(block, hostsEnd)
	// append block at end
	if len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) != "" {
		lines = append(lines, "")
	}
	lines = append(lines, block...)
	out := strings.Join(lines, "\n") + "\n"
	// write file
	return os.WriteFile(hostsPath, []byte(out), 0644)
}

func clearHostsBlock() error {
	content := ""
	if b, err := os.ReadFile(hostsPath); err == nil {
		content = string(b)
	} else {
		return nil
	}
	lines := []string{}
	scanner := bufio.NewScanner(strings.NewReader(content))
	inBlock := false
	changed := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == hostsBegin {
			inBlock = true
			changed = true
			continue
		}
		if strings.TrimSpace(line) == hostsEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			lines = append(lines, line)
		}
	}
	if !changed {
		return nil
	}
	out := strings.Join(lines, "\n")
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return os.WriteFile(hostsPath, []byte(out), 0644)
}
