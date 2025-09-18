package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

type ClientConfig struct {
	ServerURL  string   `json:"server_url"`
	Name       string   `json:"name"`
	Token      string   `json:"token"`
	DNSServers []string `json:"dns_servers"`
}

func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		ServerURL:  "",
		Name:       "",
		Token:      "",
		DNSServers: nil,
	}
}

// LoadClientConfig reads JSON from path (default config/client.json) and applies env overrides
func LoadClientConfig(path string) (ClientConfig, error) {
	if path == "" {
		path = filepath.Join("config", "client.json")
	}
	cfg := DefaultClientConfig()
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if v := os.Getenv("NETCTRL_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("NETCTRL_CLIENT_NAME"); v != "" {
		cfg.Name = v
	}
	if v := os.Getenv("NETCTRL_CLIENT_TOKEN"); v != "" {
		cfg.Token = v
	}
	if v := os.Getenv("NETCTRL_DNS_SERVERS"); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if s := strings.TrimSpace(p); s != "" {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			cfg.DNSServers = out
		}
	}
	// normalize
	cfg.ServerURL = strings.TrimSpace(cfg.ServerURL)
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.Token = strings.TrimSpace(cfg.Token)
	// trim dns servers
	if len(cfg.DNSServers) > 0 {
		cleaned := make([]string, 0, len(cfg.DNSServers))
		for _, s := range cfg.DNSServers {
			if t := strings.TrimSpace(s); t != "" {
				cleaned = append(cleaned, t)
			}
		}
		cfg.DNSServers = cleaned
	}
	return cfg, nil
}
