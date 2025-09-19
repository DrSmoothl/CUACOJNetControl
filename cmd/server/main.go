package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"cuacoj/netcontrol/pkg/config"
	"cuacoj/netcontrol/pkg/proto"
)

type clientConn struct {
	name     string
	ws       *websocket.Conn
	lastSeen time.Time
	state    proto.State
}

type hub struct {
	mu             sync.RWMutex
	clients        map[string]*clientConn
	controlEnabled bool
	domains        []string
	events         []proto.NetEvent
	staticDir      string
	clientToken    string
	whitelist      map[string]struct{}
	perClient      map[string]config.ClientOverride
	clientVersion  string
	updateDir      string
}

func newHub() *hub {
	return &hub{clients: make(map[string]*clientConn), whitelist: map[string]struct{}{}, perClient: map[string]config.ClientOverride{}}
}

// setters are handled via /api/config

func (h *hub) broadcastConfigLocked() {
	for name, c := range h.clients {
		if c.ws == nil {
			continue
		}
		cfg := h.effectiveConfig(name)
		_ = c.ws.WriteJSON(proto.Envelope{Type: proto.MsgConfig, Data: cfg})
	}
}

func (h *hub) effectiveConfig(name string) proto.Config {
	// 1) 白名单：强制不限制
	if _, ok := h.whitelist[name]; ok {
		return proto.Config{ControlEnabled: false, Domains: h.domains}
	}
	// 2) 每客户端覆盖
	if ov, ok := h.perClient[name]; ok && ov.ControlEnabled != nil {
		return proto.Config{ControlEnabled: *ov.ControlEnabled, Domains: h.domains}
	}
	// 3) 全局
	return proto.Config{ControlEnabled: h.controlEnabled, Domains: h.domains}
}

func (h *hub) addEvent(evt proto.NetEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// cap at 500
	if len(h.events) >= 500 {
		h.events = append(h.events[1:], evt)
	} else {
		h.events = append(h.events, evt)
	}
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

func (h *hub) handleWS(w http.ResponseWriter, r *http.Request) {
	// Optional token check
	if h.clientToken != "" { // h.clientToken 持有 sha256 hex 或旧明文
		got := r.URL.Query().Get("token")
		if got == "" {
			ah := r.Header.Get("Authorization")
			const p = "Bearer "
			if len(ah) > len(p) && ah[:len(p)] == p {
				got = ah[len(p):]
			}
		}
		if got == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !matchToken(got, h.clientToken) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	var name string
	c := &clientConn{ws: ws}

	// Send initial config
	h.mu.RLock()
	initCfg := proto.Config{ControlEnabled: h.controlEnabled, Domains: h.domains}
	h.mu.RUnlock()
	_ = ws.WriteJSON(proto.Envelope{Type: proto.MsgConfig, Data: initCfg})

	for {
		var env proto.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			if name != "" {
				h.mu.Lock()
				if ec, ok := h.clients[name]; ok {
					ec.ws = nil
					ec.state.Online = false
					ec.lastSeen = time.Now()
					h.clients[name] = ec
				}
				h.mu.Unlock()
			}
			_ = ws.Close()
			return
		}

		switch env.Type {
		case proto.MsgRegister:
			b, _ := json.Marshal(env.Data)
			var reg proto.Register
			_ = json.Unmarshal(b, &reg)
			name = reg.Name
			c.name = name
			c.lastSeen = time.Now()
			h.mu.Lock()
			if old, ok := h.clients[name]; ok {
				// reuse existing record
				old.ws = ws
				old.lastSeen = time.Now()
				old.state.Name = name
				old.state.Online = true
				h.clients[name] = old
				c = old
			} else {
				c.state.Name = name
				c.state.Online = true
				h.clients[name] = c
			}
			h.mu.Unlock()
		case proto.MsgHeartbeat:
			c.lastSeen = time.Now()
		case proto.MsgState:
			b, _ := json.Marshal(env.Data)
			var st proto.State
			_ = json.Unmarshal(b, &st)
			c.state = st
			c.lastSeen = time.Now()
		case proto.MsgNetEvent:
			// TODO: stream to subscribers; for now log
			b, _ := json.Marshal(env.Data)
			var evt proto.NetEvent
			if err := json.Unmarshal(b, &evt); err == nil {
				if evt.Name == "" {
					evt.Name = name
				}
				h.addEvent(evt)
			}
			log.Printf("net_event from %s: %s", name, string(b))
		}
	}
}

func (h *hub) handleAPI() http.Handler {
	mux := http.NewServeMux()

	// token 保护的包装器（静态文件与 /ws 除外）
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if h.clientToken != "" {
				// 读取 header / query
				var got string
				if v := r.Header.Get("X-Auth-Token"); v != "" {
					got = v
				}
				if got == "" {
					ah := r.Header.Get("Authorization")
					const p = "Bearer "
					if len(ah) > len(p) && ah[:len(p)] == p {
						got = ah[len(p):]
					}
				}
				if got == "" {
					got = r.URL.Query().Get("token")
				}
				if !matchToken(got, h.clientToken) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
			next(w, r)
		}
	}
	// client update metadata
	mux.HandleFunc("/api/client_update", auth(func(w http.ResponseWriter, r *http.Request) {
		osName := r.URL.Query().Get("os")
		arch := r.URL.Query().Get("arch")
		resp := struct {
			Version string `json:"version"`
			URL     string `json:"url"`
		}{Version: h.clientVersion}
		if osName != "" && arch != "" && h.updateDir != "" {
			ext := ""
			if osName == "windows" {
				ext = ".exe"
			}
			fname := "client-" + osName + "-" + arch + ext
			fpath := filepath.Join(h.updateDir, fname)
			if _, err := os.Stat(fpath); err == nil {
				resp.URL = "/download/client?os=" + osName + "&arch=" + arch
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	// client binary download
	mux.HandleFunc("/download/client", auth(func(w http.ResponseWriter, r *http.Request) {
		osName := r.URL.Query().Get("os")
		arch := r.URL.Query().Get("arch")
		if osName == "" || arch == "" {
			http.Error(w, "missing os/arch", 400)
			return
		}
		ext := ""
		if osName == "windows" {
			ext = ".exe"
		}
		fname := "client-" + osName + "-" + arch + ext
		path := filepath.Join(h.updateDir, fname)
		if _, err := os.Stat(path); err != nil {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodHead {
			w.WriteHeader(200)
			return
		}
		http.ServeFile(w, r, path)
	}))
	// admin upload client binary
	mux.HandleFunc("/admin/upload", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		osName := r.URL.Query().Get("os")
		arch := r.URL.Query().Get("arch")
		if osName == "" || arch == "" {
			http.Error(w, "missing os/arch", 400)
			return
		}
		if err := r.ParseMultipartForm(64 << 20); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		file, hdr, err := r.FormFile("file")
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		defer file.Close()
		// save file
		ext := ""
		if osName == "windows" {
			ext = ".exe"
		}
		fname := "client-" + osName + "-" + arch + ext
		if err := os.MkdirAll(h.updateDir, 0o755); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		out := filepath.Join(h.updateDir, fname)
		dst, err := os.Create(out)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if _, err := io.Copy(dst, file); err != nil {
			dst.Close()
			http.Error(w, err.Error(), 500)
			return
		}
		dst.Close()
		log.Printf("uploaded %s (%s) -> %s", hdr.Filename, osName+"-"+arch, out)
		if v := r.FormValue("version"); v != "" {
			h.mu.Lock()
			h.clientVersion = v
			h.mu.Unlock()
			if globalConfigPath != "" {
				_ = persistFull(globalConfigPath, h)
			}
		}
		w.WriteHeader(204)
	}))
	mux.HandleFunc("/api/clients", auth(func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		list := make([]proto.State, 0, len(h.clients))
		for _, c := range h.clients {
			st := c.state
			st.LastSeenUnix = c.lastSeen.Unix()
			list = append(list, st)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		_ = json.NewEncoder(w).Encode(list)
	}))
	// per-client batch config
	mux.HandleFunc("/api/clients/batch_config", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(405)
			return
		}
		var req struct {
			Names []string `json:"names"`
			// use pointer to detect null (inherit)
			ControlEnabled *bool `json:"control_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		h.mu.Lock()
		for _, n := range req.Names {
			n = trim(n)
			if n == "" {
				continue
			}
			if req.ControlEnabled == nil {
				delete(h.perClient, n)
			} else {
				h.perClient[n] = config.ClientOverride{ControlEnabled: req.ControlEnabled}
			}
		}
		// push to affected
		for _, n := range req.Names {
			if c, ok := h.clients[n]; ok && c.ws != nil {
				_ = c.ws.WriteJSON(proto.Envelope{Type: proto.MsgConfig, Data: h.effectiveConfig(n)})
			}
		}
		// persist
		if globalConfigPath != "" {
			if err := persistFull(globalConfigPath, h); err != nil {
				log.Printf("persist batch failed: %v", err)
			}
		}
		h.mu.Unlock()
		w.WriteHeader(204)
	}))
	mux.HandleFunc("/api/config", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.mu.RLock()
			defer h.mu.RUnlock()
			_ = json.NewEncoder(w).Encode(proto.Config{ControlEnabled: h.controlEnabled, Domains: h.domains})
		case http.MethodPost:
			var cfg proto.Config
			if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			h.mu.Lock()
			h.controlEnabled = cfg.ControlEnabled
			h.domains = append([]string(nil), cfg.Domains...)
			h.broadcastConfigLocked()
			h.mu.Unlock()
			// persist to disk if config file exists
			if globalConfigPath != "" {
				if err := persistFull(globalConfigPath, h); err != nil {
					log.Printf("persist config failed: %v", err)
				}
			}
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	// whitelist endpoints
	mux.HandleFunc("/api/whitelist", auth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.mu.RLock()
			defer h.mu.RUnlock()
			names := make([]string, 0, len(h.whitelist))
			for n := range h.whitelist {
				names = append(names, n)
			}
			sort.Strings(names)
			_ = json.NewEncoder(w).Encode(struct {
				Names []string `json:"names"`
			}{Names: names})
		case http.MethodPost:
			var req struct {
				Names []string `json:"names"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			h.mu.Lock()
			h.whitelist = map[string]struct{}{}
			for _, n := range req.Names {
				n = trim(n)
				if n != "" {
					h.whitelist[n] = struct{}{}
				}
			}
			// broadcast new effective configs
			h.broadcastConfigLocked()
			// persist
			if globalConfigPath != "" {
				if err := persistFull(globalConfigPath, h); err != nil {
					log.Printf("persist whitelist failed: %v", err)
				}
			}
			h.mu.Unlock()
			w.WriteHeader(204)
		default:
			w.WriteHeader(405)
		}
	}))
	mux.HandleFunc("/api/events", auth(func(w http.ResponseWriter, r *http.Request) {
		h.mu.RLock()
		defer h.mu.RUnlock()
		_ = json.NewEncoder(w).Encode(h.events)
	}))
	// static admin UI
	fs := http.FileServer(http.Dir(h.staticDir))
	mux.Handle("/", fs)
	mux.HandleFunc("/ws", h.handleWS)
	return mux
}

// UI 已改为外部静态文件

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "config/server.json", "server config file (json), priority: file > env > default")
	flag.Parse()

	setupLogging("server")

	cfg, err := config.LoadServerConfig(cfgPath)
	if err != nil {
		log.Printf("config load warning: %v", err)
		// continue with defaults/env
		cfg, _ = config.LoadServerConfig("")
	}

	h := newHub()
	// initialize global config to clients
	h.controlEnabled = cfg.ControlEnabled
	h.domains = append([]string(nil), cfg.InitialDomains...)
	h.staticDir = cfg.StaticDir
	// Token: 若 data/token 存在则读取哈希；否则首次生成随机 token 输出给管理员并存储其哈希
	if cfg.ClientToken != "" { // 兼容旧方式（纯文本）
		// 直接使用旧字段（明文）
		h.clientToken = cfg.ClientToken
	} else {
		plain, hashed, first, err := ensureTokenHash()
		if err != nil {
			log.Printf("token init error: %v", err)
		} else {
			h.clientToken = hashed
			if first {
				log.Printf("[SECURITY] 初次启动生成管理访问 Token: %s", plain)
				log.Printf("请妥善保存；此 Token 仅显示一次，后端仅保存其哈希。重置请删除 data/token 再重启。")
			}
		}
	}
	h.clientVersion = cfg.ClientVersion
	h.updateDir = cfg.UpdateDir
	for _, n := range cfg.WhitelistClients {
		if s := trim(n); s != "" {
			h.whitelist[s] = struct{}{}
		}
	}
	if cfg.PerClient != nil {
		h.perClient = cfg.PerClient
	}

	srv := &http.Server{Addr: cfg.Addr, Handler: h.handleAPI()}
	log.Printf("server listening on %s (tls=%v, static=%s)", cfg.Addr, cfg.TLS.Enable, cfg.StaticDir)

	// hot reload watcher
	globalConfigPath = cfgPath
	if cfgPath != "" {
		go watchConfig(cfgPath, h)
	}

	if cfg.TLS.Enable {
		log.Fatal(srv.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile))
	} else {
		log.Fatal(srv.ListenAndServe())
	}
}

var globalConfigPath string

func watchConfig(path string, h *hub) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("watcher error: %v", err)
		return
	}
	defer w.Close()
	abs, e := filepath.Abs(path)
	if e != nil {
		log.Printf("abs path error: %v", e)
		return
	}
	dir := filepath.Dir(abs)
	if err := w.Add(dir); err != nil {
		log.Printf("watch add error: %v", err)
		return
	}
	for {
		select {
		case ev := <-w.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 && filepathBase(ev.Name) == filepathBase(abs) {
				// reload
				sc, err := config.LoadServerConfig(abs)
				if err != nil {
					log.Printf("reload config failed: %v", err)
					continue
				}
				h.mu.Lock()
				h.controlEnabled = sc.ControlEnabled
				h.domains = append([]string(nil), sc.InitialDomains...)
				h.clientVersion = sc.ClientVersion
				h.updateDir = sc.UpdateDir
				// reload whitelist
				h.whitelist = map[string]struct{}{}
				for _, n := range sc.WhitelistClients {
					if s := trim(n); s != "" {
						h.whitelist[s] = struct{}{}
					}
				}
				// reload per-client overrides
				if sc.PerClient != nil {
					h.perClient = sc.PerClient
				} else {
					h.perClient = map[string]config.ClientOverride{}
				}
				// broadcast new effective configs
				h.broadcastConfigLocked()
				h.mu.Unlock()
				log.Printf("config reloaded: %s", abs)
			}
		case err := <-w.Errors:
			log.Printf("watch error: %v", err)
		}
	}
}

func filepathBase(p string) string {
	i := len(p) - 1
	for ; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			break
		}
	}
	return p[i+1:]
}

func trim(s string) string { return strings.TrimSpace(s) }

// setupLogging configures rotating file logs at logs/server.log and also writes to stdout.
func setupLogging(app string) {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	dir := filepath.Join(base, "logs")
	_ = os.MkdirAll(dir, 0o755)
	file := filepath.Join(dir, app+".log")
	maxSize := getEnvInt("NETCTRL_LOG_MAX_SIZE_MB", 20)
	maxBackups := getEnvInt("NETCTRL_LOG_MAX_BACKUPS", 5)
	maxAge := getEnvInt("NETCTRL_LOG_MAX_AGE_DAYS", 7)
	w := &lumberjack.Logger{Filename: file, MaxSize: maxSize, MaxBackups: maxBackups, MaxAge: maxAge, Compress: false}
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(io.MultiWriter(os.Stdout, w))
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// persistFull writes the full server configuration back to disk, preserving unrelated fields
// like TLS, static_dir, and client_token from the existing file. It updates:
// - control_enabled
// - initial_domains
// - whitelist_clients
// - per_client
func persistFull(path string, h *hub) error {
	if path == "" {
		return nil
	}
	// Load current to preserve unrelated fields
	sc, err := config.LoadServerConfig(path)
	if err != nil {
		return err
	}
	h.mu.RLock()
	sc.ControlEnabled = h.controlEnabled
	sc.InitialDomains = append([]string(nil), h.domains...)
	// dump whitelist
	names := make([]string, 0, len(h.whitelist))
	for n := range h.whitelist {
		names = append(names, n)
	}
	sort.Strings(names)
	sc.WhitelistClients = names
	// dump per-client overrides (shallow copy)
	if h.perClient != nil {
		sc.PerClient = make(map[string]config.ClientOverride, len(h.perClient))
		for k, v := range h.perClient {
			sc.PerClient[k] = v
		}
	} else {
		sc.PerClient = nil
	}
	h.mu.RUnlock()

	// Marshal and write
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		return err
	}
	// Ensure directory exists
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(path, b, 0o644)
}

// ensureTokenHash ensures a token hash file exists under data/token.
// Returns (plainToken, hashed, firstCreated, error)
func ensureTokenHash() (string, string, bool, error) {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	dataDir := filepath.Join(base, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return "", "", false, err
	}
	tokenFile := filepath.Join(dataDir, "token")
	if b, err := os.ReadFile(tokenFile); err == nil {
		// already stored hashed (hex)
		hash := strings.TrimSpace(string(b))
		return "", hash, false, nil
	}
	// generate new
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", false, err
	}
	plain := encodeToken(raw)
	sum := sha256.Sum256([]byte(plain))
	hashed := fmt.Sprintf("%x", sum[:])
	if err := os.WriteFile(tokenFile, []byte(hashed), 0o600); err != nil {
		return "", "", false, err
	}
	return plain, hashed, true, nil
}

func encodeToken(b []byte) string {
	s := base64.RawURLEncoding.EncodeToString(b)
	return s
}

// matchToken 支持两种情况：storedHash 可能是旧明文，或是 sha256 hex
func matchToken(provided, stored string) bool {
	if provided == "" || stored == "" {
		return false
	}
	if len(stored) == 64 { // 可能是 sha256 hex
		sum := sha256.Sum256([]byte(provided))
		ph := fmt.Sprintf("%x", sum[:])
		if len(ph) != len(stored) {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(ph), []byte(stored)) == 1
	}
	// fallback 明文比较
	if len(provided) != len(stored) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(provided), []byte(stored)) == 1
}
