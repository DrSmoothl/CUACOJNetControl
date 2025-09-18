package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type TLSConfig struct {
	Enable   bool   `json:"enable"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
}

type ServerConfig struct {
	Addr             string                    `json:"addr"`
	TLS              TLSConfig                 `json:"tls"`
	ClientToken      string                    `json:"client_token"`
	StaticDir        string                    `json:"static_dir"`
	InitialDomains   []string                  `json:"initial_domains"`
	ControlEnabled   bool                      `json:"control_enabled"`
	WhitelistClients []string                  `json:"whitelist_clients"`
	PerClient        map[string]ClientOverride `json:"per_client"`
	// Client update metadata
	ClientVersion string `json:"client_version"`
	UpdateDir     string `json:"update_dir"`
}

type ClientOverride struct {
	// if nil => inherit global; if set => override
	ControlEnabled *bool `json:"control_enabled,omitempty"`
}

func defaultConfig() ServerConfig {
	return ServerConfig{
		Addr:             ":8080",
		StaticDir:        "web/admin",
		InitialDomains:   nil,
		ControlEnabled:   false,
		WhitelistClients: nil,
		PerClient:        map[string]ClientOverride{},
		ClientVersion:    "",
		UpdateDir:        "updates",
	}
}

func LoadServerConfig(path string) (ServerConfig, error) {
	cfg := defaultConfig()
	// file optional
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			ext := strings.ToLower(filepath.Ext(path))
			switch ext {
			case ".json":
				if err := json.Unmarshal(b, &cfg); err != nil {
					return cfg, fmt.Errorf("parse json: %w", err)
				}
			case ".yaml", ".yml":
				// very small YAML -> JSON fallback (no external deps): not supported; suggest json
				return cfg, errors.New("yaml not supported in minimal build; use JSON")
			default:
				return cfg, fmt.Errorf("unsupported config extension: %s", ext)
			}
		}
	}

	// env overrides
	if v := os.Getenv("NETCTRL_ADDR"); v != "" {
		cfg.Addr = v
	}
	if v := os.Getenv("NETCTRL_TLS_ENABLE"); v != "" {
		cfg.TLS.Enable = (v == "1" || strings.ToLower(v) == "true")
	}
	if v := os.Getenv("NETCTRL_TLS_CERT"); v != "" {
		cfg.TLS.CertFile = v
	}
	if v := os.Getenv("NETCTRL_TLS_KEY"); v != "" {
		cfg.TLS.KeyFile = v
	}
	if v := os.Getenv("NETCTRL_CLIENT_TOKEN"); v != "" {
		cfg.ClientToken = v
	}
	if v := os.Getenv("NETCTRL_STATIC_DIR"); v != "" {
		cfg.StaticDir = v
	}
	if v := os.Getenv("NETCTRL_INITIAL_DOMAINS"); v != "" {
		cfg.InitialDomains = splitCSV(v)
	}
	if v := os.Getenv("NETCTRL_CONTROL_ENABLED"); v != "" {
		cfg.ControlEnabled = (v == "1" || strings.ToLower(v) == "true")
	}
	if v := os.Getenv("NETCTRL_WHITELIST_CLIENTS"); v != "" {
		cfg.WhitelistClients = splitCSV(v)
		if v := os.Getenv("NETCTRL_CLIENT_VERSION"); v != "" {
			cfg.ClientVersion = v
		}
		if v := os.Getenv("NETCTRL_UPDATE_DIR"); v != "" {
			cfg.UpdateDir = v
		}
	}

	return cfg, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
