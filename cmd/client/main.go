package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/gorilla/websocket"
	svc "github.com/kardianos/service"
	gnet "github.com/shirou/gopsutil/v3/net"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	mdns "github.com/miekg/dns"

	cfgpkg "cuacoj/netcontrol/pkg/config"
	"cuacoj/netcontrol/pkg/proto"
)

var version = "0.1.0"

// resolveDomainsMap resolves domains to IPs (A/AAAA), following CNAMEs.
// Prefer enhanced miekg/dns with configurable servers, fallback to net.LookupIP.
func resolveDomainsMapWithServers(domains []string, servers []string) (map[string]string, []net.IP) {
	ipToDomain := map[string]string{}
	uniq := map[string]struct{}{}
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		variants := []string{d}
		if !strings.HasPrefix(d, "www.") {
			variants = append(variants, "www."+d)
		}
		for _, name := range variants {
			ips := resolveOneName(name, servers)
			if len(ips) == 0 {
				// fallback to Go resolver
				if sys, err := net.LookupIP(name); err == nil {
					ips = sys
				}
			}
			for _, ip := range ips {
				s := ip.String()
				uniq[s] = struct{}{}
				if _, ok := ipToDomain[s]; !ok {
					ipToDomain[s] = d
				}
			}
		}
	}
	out := make([]net.IP, 0, len(uniq))
	for s := range uniq {
		out = append(out, net.ParseIP(s))
	}
	return ipToDomain, out
}

func parseDNSServers(env string) []string {
	var out []string
	for _, part := range strings.Split(env, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s = s + ":53"
		}
		out = append(out, s)
	}
	// sensible defaults if none provided
	if len(out) == 0 {
		out = []string{"127.0.0.1:53", "223.5.5.5:53", "114.114.114.114:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	return out
}

// resolveOneName resolves A+AAAA, following up to 5 CNAME hops.
func resolveOneName(name string, servers []string) []net.IP {
	seen := map[string]struct{}{}
	var acc []net.IP
	// helper to query RR type
	q := func(fqdn string, qtype uint16) ([]mdns.RR, error) {
		m := new(mdns.Msg)
		m.SetQuestion(mdns.Fqdn(fqdn), qtype)
		c := new(mdns.Client)
		for _, srv := range servers {
			in, _, err := c.Exchange(m, srv)
			if err == nil && in != nil && in.Rcode == mdns.RcodeSuccess {
				return append(in.Answer, in.Extra...), nil
			}
			if os.Getenv("NETCTRL_DEBUG") != "" {
				rc := -1
				if in != nil { rc = in.Rcode }
				log.Printf("[DNS] query %s type %d via %s err=%v rcode=%d", fqdn, qtype, srv, err, rc)
			}
		}
		return nil, fmt.Errorf("no answer")
	}
	target := name
	for hop := 0; hop < 5; hop++ {
		// A records
		if rr, _ := q(target, mdns.TypeA); rr != nil {
			for _, r := range rr {
				if a, ok := r.(*mdns.A); ok {
					ip := a.A
					if _, ok := seen[ip.String()]; !ok {
						seen[ip.String()] = struct{}{}
						acc = append(acc, ip)
					}
				}
				if cn, ok := r.(*mdns.CNAME); ok {
					target = strings.TrimSuffix(cn.Target, ".")
				}
			}
		}
		// AAAA records
		if rr, _ := q(target, mdns.TypeAAAA); rr != nil {
			for _, r := range rr {
				if aaaa, ok := r.(*mdns.AAAA); ok {
					ip := aaaa.AAAA
					if _, ok := seen[ip.String()]; !ok {
						seen[ip.String()] = struct{}{}
						acc = append(acc, ip)
					}
				}
				if cn, ok := r.(*mdns.CNAME); ok {
					target = strings.TrimSuffix(cn.Target, ".")
				}
			}
		}
		// if we got any IPs, stop; else continue to follow CNAME
		if len(acc) > 0 {
			break
		}
	}
	return acc
}

func main() {
	setupLogging("client")
	// On Windows, prompt for elevation and relaunch as admin if needed
	ensureElevated()
	// preload client.json as defaults
	cc, _ := cfgpkg.LoadClientConfig("")
	defURL := cc.ServerURL
	if defURL == "" {
		defURL = "ws://127.0.0.1:8080/ws"
	}
	server := flag.String("server", defURL, "server ws url (env NETCTRL_SERVER_URL or config/client.json)")
	name := flag.String("name", cc.Name, "client name (env NETCTRL_CLIENT_NAME or config)")
	token := flag.String("token", cc.Token, "auth token (env NETCTRL_CLIENT_TOKEN or config)")
	svcCmd := flag.String("service", "", "service control: install|uninstall|start|stop (Windows/Linux supported)")
	svcName := flag.String("svcname", "CUACOJNetControlClient", "service name")
	stopPassFlag := flag.String("stoppass", "", "stop password (for service stop command and console Ctrl+C)")
	flag.Parse()
	if *name == "" {
		hn, _ := os.Hostname()
		*name = hn
	}

	// Try client auto-update before starting WS: query /api/client_update
	_ = trySelfUpdate(*server, *name, *token)

	// Watch client.json for changes and trigger reconnect when server URL/token change
	reconnectCh := make(chan struct{}, 1)
	go watchClientConfig(reconnectCh)

	// Service control path
	if *svcCmd != "" {
		if err := handleServiceCmd(*svcCmd, *svcName, *server, *name, *token, *stopPassFlag); err != nil {
			log.Fatalf("service %s failed: %v", *svcCmd, err)
		}
		return
	}

	// Optional stop password in console mode
	stopPass := *stopPassFlag
	if os.Getenv("NETCTRL_DEBUG") != "" { log.Printf("[BOOT] debug on, version=%s", version) }
	if stopPass == "" {
		stopPass = os.Getenv("NETCTRL_STOP_PASSWORD")
	}
	if stopPass != "" {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
		go func() {
			for range sigc {
				fmt.Print("请输入停止密码: ")
				r := bufio.NewReader(os.Stdin)
				line, _ := r.ReadString('\n')
				line = strings.TrimSpace(line)
				if line == stopPass {
					fmt.Println("密码正确，正在退出...")
					os.Exit(0)
				} else {
					fmt.Println("密码错误，继续运行")
				}
			}
		}()
	}

	curServer, curName, curToken := *server, *name, *token
	for {
		if err := run(curServer, curName, curToken); err != nil {
			log.Printf("disconnected: %v; retry in 3s", err)
			// check if config changed requests reconnect
			select {
			case <-reconnectCh:
				// reload config
				nc, _ := cfgpkg.LoadClientConfig("")
				if nc.ServerURL != "" {
					curServer = nc.ServerURL
				}
				if nc.Name != "" {
					curName = nc.Name
				}
				if nc.Token != "" {
					curToken = nc.Token
				}
			default:
			}
			time.Sleep(3 * time.Second)
		}
	}
}

func run(url, name, token string) error {
	header := http.Header{}
	if token != "" {
		header.Set("Authorization", "Bearer "+token)
	}
	ws, _, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		return err
	}
	defer ws.Close()

	// register
	_ = ws.WriteJSON(proto.Envelope{Type: proto.MsgRegister, Data: proto.Register{Name: name, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: version}})

	// state
	controlEnabled := false
	allowedDomains := []string{}
	allowedIPDomain := map[string]string{}

	// heartbeat ticker
	hb := time.NewTicker(10 * time.Second)
	defer hb.Stop()

	// domain refresh ticker
	refresh := time.NewTicker(20 * time.Second)
	defer refresh.Stop()

	// platform functions (no-op on non-windows)
	apply := func() {}
	clear := func() {}

	// platform-specific imports via build tags
	if runtime.GOOS == "windows" {
		apply = func() {
			// prefer servers from config then env
			cc, _ := cfgpkg.LoadClientConfig("")
			servers := cc.DNSServers
			if len(servers) == 0 {
				servers = parseDNSServers(os.Getenv("NETCTRL_DNS_SERVERS"))
			}
			if os.Getenv("NETCTRL_DEBUG") != "" { log.Printf("[APPLY] domains=%v dns=%v", allowedDomains, servers) }
			m, ips := resolveDomainsMapWithServers(allowedDomains, servers)
			allowedIPDomain = m
			// update hosts file to pin domains -> IPs (help against DoH bypass)
			domToIPs := map[string][]net.IP{}
			for ipStr, d := range m {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				domToIPs[d] = append(domToIPs[d], ip)
			}
			if os.Getenv("NETCTRL_DEBUG") != "" { log.Printf("[APPLY] resolved IPs=%v", ips) }
			_ = fwApply(controlEnabled, ips)
			if controlEnabled {
				allowServerByURL(url)
				_ = updateHosts(domToIPs)
			}
		}
		clear = func() {
			_ = fwClear()
			_ = clearHostsBlock()
		}
	}

	sendState := func() {
		st := proto.State{Name: name, ControlEnabled: controlEnabled, AllowedDomains: allowedDomains, Online: true, LastSeenUnix: time.Now().Unix()}
		_ = ws.WriteJSON(proto.Envelope{Type: proto.MsgState, Data: st})
	}

	// initial state
	sendState()

	// connection monitor with debounce and rate limiting
	seen := map[string]time.Time{} // remote -> last time seen (debounce window)
	prune := func(now time.Time) {
		for k, t := range seen {
			if now.Sub(t) > 60*time.Second {
				delete(seen, k)
			}
		}
	}

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		maxPerTick := getEnvInt("NETCTRL_EVENT_MAX_PER_TICK", 100)
		maxPerMin := getEnvInt("NETCTRL_EVENT_MAX_PER_MIN", 1000)
		minuteStart := time.Now()
		minuteSent := 0
		for range ticker.C {
			conns, err := gnet.Connections("tcp")
			if err != nil {
				continue
			}
			now := time.Now()
			prune(now)
			if now.Sub(minuteStart) >= time.Minute {
				minuteStart = now
				minuteSent = 0
			}
			tickSent := 0
			suppressed := 0
			for _, c := range conns {
				if c.Status != "ESTABLISHED" {
					continue
				}
				if c.Raddr.IP == "" {
					continue
				}
				key := c.Raddr.IP + ":" + fmt.Sprintf("%d", c.Raddr.Port)
				if t, ok := seen[key]; ok {
					// debounce: skip if seen in last 10s
					if now.Sub(t) < 10*time.Second {
						continue
					}
				}
				// rate limits
				if tickSent >= maxPerTick || minuteSent >= maxPerMin {
					suppressed++
					continue
				}
				seen[key] = now
				dom, ok := allowedIPDomain[c.Raddr.IP]
				allowed := ok
				// always treat loopback as allowed
				if c.Raddr.IP == "127.0.0.1" || c.Raddr.IP == "::1" {
					allowed = true
				}
				evt := proto.NetEvent{Name: name, TimeUnix: now.Unix(), Proto: "tcp", RemoteIP: c.Raddr.IP, RemotePort: int(c.Raddr.Port), Allowed: allowed, Domain: dom}
				if err := ws.WriteJSON(proto.Envelope{Type: proto.MsgNetEvent, Data: evt}); err == nil {
					tickSent++
					minuteSent++
				}
			}
			if suppressed > 0 {
				note := fmt.Sprintf("suppressed %d events (rate-limited)", suppressed)
				sum := proto.NetEvent{Name: name, TimeUnix: time.Now().Unix(), Proto: "summary", Allowed: true, Note: note}
				_ = ws.WriteJSON(proto.Envelope{Type: proto.MsgNetEvent, Data: sum})
				log.Printf("event rate-limited: %s", note)
			}
		}
	}()

	go func() {
		for range hb.C {
			_ = ws.WriteJSON(proto.Envelope{Type: proto.MsgHeartbeat, Data: proto.Heartbeat{Name: name, UptimeMs: int64(time.Since(startTime).Milliseconds())}})
		}
	}()

	for {
		// non-blocking apply
		select {
		case <-refresh.C:
			if controlEnabled {
				apply()
			}
		default:
		}

		var env proto.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			clear()
			return err
		}
		switch env.Type {
		case proto.MsgConfig:
			b, _ := json.Marshal(env.Data)
			var cfg proto.Config
			if err := json.Unmarshal(b, &cfg); err == nil {
				controlEnabled = cfg.ControlEnabled
				allowedDomains = cfg.Domains
				if controlEnabled {
					apply()
				} else {
					clear()
				}
				sendState()
			}
		}
	}
}

var startTime = time.Now()

// Windows specific wrappers (linked via conditional file on windows)

// ---- Service integration ----
type program struct{ url, name, token string }

func (p *program) Start(s svc.Service) error {
	go func() {
		for {
			if err := run(p.url, p.name, p.token); err != nil {
				time.Sleep(3 * time.Second)
			}
		}
	}()
	return nil
}

func (p *program) Stop(s svc.Service) error {
	// For simplicity, exit process; SCM will consider service stopped
	os.Exit(0)
	return nil
}

func handleServiceCmd(cmd, name, url, clientName, token, stopPass string) error {
	cfg := &svc.Config{
		Name:        name,
		DisplayName: name,
		Description: "CUACOJ NetControl 客户端服务",
		Option:      map[string]interface{}{"Restart": "on-failure", "RunAtLoad": true, "StartType": "automatic"},
	}
	p := &program{url: url, name: clientName, token: token}
	s, err := svc.New(p, cfg)
	if err != nil {
		return err
	}
	switch strings.ToLower(cmd) {
	case "install":
		return s.Install()
	case "uninstall":
		return s.Uninstall()
	case "start":
		return s.Start()
	case "stop":
		// Require password if configured
		want := os.Getenv("NETCTRL_STOP_PASSWORD")
		if want == "" {
			want = stopPass
		}
		if want != "" && stopPass != want {
			return fmt.Errorf("stop password required or mismatch")
		}
		return s.Stop()
	case "run":
		return s.Run()
	default:
		return fmt.Errorf("unknown service command: %s", cmd)
	}
}

// logging setup similar to server
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

// --- Self update ---
func trySelfUpdate(serverURL, name, token string) error {
	// Build API url base: replace /ws with empty
	base := strings.TrimSuffix(serverURL, "/ws")
	// add API path
	osName := runtime.GOOS
	arch := runtime.GOARCH
	api := base
	if strings.HasPrefix(api, "ws:") {
		api = "http:" + api[3:]
	}
	if strings.HasPrefix(api, "wss:") {
		api = "https:" + api[4:]
	}
	checkURL := fmt.Sprintf("%s/api/client_update?os=%s&arch=%s", api, osName, arch)
	req, _ := http.NewRequest("GET", checkURL, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var meta struct{ Version, URL string }
	_ = json.NewDecoder(resp.Body).Decode(&meta)
	if meta.Version == "" || meta.URL == "" {
		return nil
	}
	// compare versions; if different, download and replace
	if meta.Version == version {
		return nil
	}
	// download
	dreq, _ := http.NewRequest("GET", meta.URL, nil)
	if token != "" {
		dreq.Header.Set("Authorization", "Bearer "+token)
	}
	dresp, err := http.DefaultClient.Do(dreq)
	if err != nil {
		return err
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != 200 {
		return fmt.Errorf("download status %d", dresp.StatusCode)
	}
	exe, _ := os.Executable()
	bak := exe + ".old"
	// write to temp
	tmp := exe + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, dresp.Body); err != nil {
		f.Close()
		return err
	}
	f.Close()
	// on windows: cannot overwrite running exe; rename then move
	_ = os.Rename(exe, bak)
	if err := os.Rename(tmp, exe); err != nil {
		// rollback
		_ = os.Rename(bak, exe)
		return err
	}
	// optional: delete bak
	_ = os.Remove(bak)
	log.Printf("self-updated to version %s (downloaded)", meta.Version)
	// restart process to take effect
	os.Exit(0)
	return nil
}

// watchClientConfig watches config/client.json and notifies reconnectCh when server_url or token changed
func watchClientConfig(reconnectCh chan struct{}) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	defer w.Close()
	path := filepath.Join("config", "client.json")
	abs, _ := filepath.Abs(path)
	dir := filepath.Dir(abs)
	if err := w.Add(dir); err != nil {
		return
	}
	last := time.Now()
	for {
		select {
		case ev := <-w.Events:
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 && filepath.Base(ev.Name) == filepath.Base(abs) {
				// debounce 500ms
				if time.Since(last) < 500*time.Millisecond {
					continue
				}
				last = time.Now()
				// notify reconnect
				select {
				case reconnectCh <- struct{}{}:
				default:
				}
			}
		case <-w.Errors:
		}
	}
}
