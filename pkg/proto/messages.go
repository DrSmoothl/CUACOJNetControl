package proto

// Wire protocol (JSON over WebSocket)

type MsgType string

const (
	MsgRegister  MsgType = "register"
	MsgHeartbeat MsgType = "heartbeat"
	MsgState     MsgType = "state"
	MsgCommand   MsgType = "command"
	MsgConfig    MsgType = "config"
	MsgNetEvent  MsgType = "net_event"
)

// Envelope wraps all messages
type Envelope struct {
	Type MsgType     `json:"type"`
	Data interface{} `json:"data"`
}

// Register from client
type Register struct {
	Name    string `json:"name"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"` // client agent version
}

// Heartbeat from client
type Heartbeat struct {
	Name     string `json:"name"`
	UptimeMs int64  `json:"uptime_ms"`
}

// State reported by client
type State struct {
	Name           string   `json:"name"`
	Online         bool     `json:"online"`
	ControlEnabled bool     `json:"control_enabled"`
	AllowedDomains []string `json:"allowed_domains"`
	LastSeenUnix   int64    `json:"last_seen_unix"`
	LastError      string   `json:"last_error,omitempty"`
}

// Command sent by server
type Command struct {
	Action  string   `json:"action"` // "enable", "disable", "set_domains"
	Domains []string `json:"domains,omitempty"`
}

// Config push from server (authoritative)
type Config struct {
	ControlEnabled bool     `json:"control_enabled"`
	Domains        []string `json:"domains"`
}

// NetEvent streaming from client
type NetEvent struct {
	Name       string `json:"name"`
	TimeUnix   int64  `json:"time_unix"`
	Proto      string `json:"proto"` // tcp/udp
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Allowed    bool   `json:"allowed"`
	Domain     string `json:"domain,omitempty"`
	Note       string `json:"note,omitempty"`
}
