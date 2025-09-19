package proxy

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Controller 管理本地 HTTP(S) 代理，基于白名单域名放行，其余直接拒绝。
type Controller struct {
	Addr        string // 监听地址，例如 127.0.0.1:8888
	Resolver    *MultiResolver
	WhitelistMu sync.RWMutex
	Whitelist   map[string]struct{} // 域名（不含端口）
	ln          net.Listener
	quit        chan struct{}
	wg          sync.WaitGroup
}

func NewController(addr string, r *MultiResolver) *Controller {
	return &Controller{Addr: addr, Resolver: r, Whitelist: map[string]struct{}{}, quit: make(chan struct{})}
}

func (c *Controller) SetWhitelist(domains []string) {
	c.WhitelistMu.Lock()
	c.Whitelist = map[string]struct{}{}
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		c.Whitelist[d] = struct{}{}
	}
	c.WhitelistMu.Unlock()
}

func (c *Controller) allowed(host string) bool {
	h := strings.ToLower(host)
	if i := strings.Index(h, ":"); i >= 0 {
		h = h[:i]
	}
	c.WhitelistMu.RLock()
	_, ok := c.Whitelist[h]
	c.WhitelistMu.RUnlock()
	return ok
}

func (c *Controller) Start() error {
	if c.ln != nil {
		return errors.New("already started")
	}
	ln, err := net.Listen("tcp", c.Addr)
	if err != nil {
		return err
	}
	c.ln = ln
	c.wg.Add(1)
	go c.acceptLoop()
	log.Printf("[PROXY] listening on %s", c.Addr)
	// 尝试设置系统代理（忽略错误）
	_ = EnableSystemProxy(c.Addr)
	return nil
}

func (c *Controller) acceptLoop() {
	defer c.wg.Done()
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			select {
			case <-c.quit:
				return
			default:
			}
			continue
		}
		c.wg.Add(1)
		go func() { defer c.wg.Done(); c.handleConn(conn) }()
	}
}

func (c *Controller) Stop() error {
	if c.ln == nil {
		return nil
	}
	close(c.quit)
	_ = c.ln.Close()
	c.wg.Wait()
	c.ln = nil
	_ = DisableSystemProxy()
	log.Printf("[PROXY] stopped")
	return nil
}

func (c *Controller) handleConn(client net.Conn) {
	// 设置短读超时防止空连接
	_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(client)
	peek, err := r.Peek(1)
	if err != nil {
		client.Close()
		return
	}
	_ = peek
	// HTTP 请求头解析
	req, err := http.ReadRequest(r)
	if err != nil {
		client.Close()
		return
	}
	host := req.Host
	if !c.allowed(host) {
		io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
		client.Close()
		log.Printf("[PROXY] DENY host=%s", host)
		return
	}
	log.Printf("[PROXY] ALLOW host=%s method=%s", host, req.Method)
	if req.Method == http.MethodConnect { // HTTPS 隧道
		c.handleConnect(client, host)
		return
	}
	c.handleHTTPForward(client, req)
}

func (c *Controller) handleConnect(client net.Conn, host string) {
	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	// 直接 TCP 透传，不做 MITM。提取 SNI 需 MITM 或 peek TLS ClientHello，这里简单跳过。
	serverConn, err := net.DialTimeout("tcp", host, 10*time.Second)
	if err != nil {
		client.Close()
		return
	}
	pipe := func(a, b net.Conn) { defer a.Close(); defer b.Close(); io.Copy(a, b) }
	go pipe(client, serverConn)
	pipe(serverConn, client)
}

func (c *Controller) handleHTTPForward(client net.Conn, req *http.Request) {
	// 透传普通 HTTP
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 15 * time.Second
	resp, err := transport.RoundTrip(req)
	if err != nil {
		io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length:0\r\n\r\n")
		client.Close()
		return
	}
	defer resp.Body.Close()
	resp.Write(client)
	client.Close()
}

// 可扩展：通过解析 TLS ClientHello 获取 SNI，再次核对白名单。
// func extractSNI(clientHello []byte) (string, error) {
// 	_ = tls.ClientHelloInfo{}
// 	return "", errors.New("not implemented")
// }
