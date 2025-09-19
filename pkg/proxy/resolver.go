package proxy

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// MultiResolver 提供多上游、并发、超时、最少IP数量保证与简单缓存。
type MultiResolver struct {
	servers   []string      // host:port
	minPerDom int           // 每域最少需要多少条 IP
	timeout   time.Duration // 单服务器查询超时
	cacheTTL  time.Duration
	mu        sync.RWMutex
	cache     map[string]cacheEntry
}

type cacheEntry struct {
	ips     []net.IP
	expires time.Time
}

func NewMultiResolver(servers []string, minPer int, perTimeout, cacheTTL time.Duration) *MultiResolver {
	var norm []string
	for _, s := range servers {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		norm = append(norm, s)
	}
	if len(norm) == 0 {
		norm = []string{"127.0.0.1:53", "223.5.5.5:53", "114.114.114.114:53", "8.8.8.8:53", "1.1.1.1:53"}
	}
	return &MultiResolver{servers: norm, minPerDom: minPer, timeout: perTimeout, cacheTTL: cacheTTL, cache: map[string]cacheEntry{}}
}

// Resolve 返回去重后的 IP；不足 minPerDom 时会使用所有上游并尽可能补足。
func (r *MultiResolver) Resolve(domain string) ([]net.IP, error) {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil, errors.New("empty domain")
	}
	// cache
	r.mu.RLock()
	if ce, ok := r.cache[domain]; ok && time.Now().Before(ce.expires) {
		ipsCopy := append([]net.IP{}, ce.ips...)
		r.mu.RUnlock()
		return ipsCopy, nil
	}
	r.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()

	// first wave: query servers sequentially until gather minPerDom
	var collected []net.IP
	seen := map[string]struct{}{}
	for _, s := range r.servers {
		ips := queryOne(ctx, domain, s)
		for _, ip := range ips {
			if ip == nil {
				continue
			}
			if _, o := seen[ip.String()]; !o {
				seen[ip.String()] = struct{}{}
				collected = append(collected, ip)
			}
		}
		if len(collected) >= r.minPerDom {
			break
		}
	}
	// if still insufficient, fire concurrent to remaining (if any)
	if len(collected) < r.minPerDom {
		var wg sync.WaitGroup
		mu := sync.Mutex{}
		for _, s := range r.servers {
			wg.Add(1)
			go func(server string) {
				defer wg.Done()
				ctx2, cancel2 := context.WithTimeout(context.Background(), r.timeout)
				defer cancel2()
				ips := queryOne(ctx2, domain, server)
				if len(ips) == 0 {
					return
				}
				mu.Lock()
				for _, ip := range ips {
					if ip == nil {
						continue
					}
					if _, o := seen[ip.String()]; !o {
						seen[ip.String()] = struct{}{}
						collected = append(collected, ip)
					}
				}
				mu.Unlock()
			}(s)
		}
		wg.Wait()
	}
	if len(collected) == 0 {
		return nil, errors.New("no ips")
	}
	// stable order
	sort.Slice(collected, func(i, j int) bool { return collected[i].String() < collected[j].String() })
	// cache store
	r.mu.Lock()
	r.cache[domain] = cacheEntry{ips: collected, expires: time.Now().Add(r.cacheTTL)}
	r.mu.Unlock()
	return collected, nil
}

// queryOne 简化实现：使用 net.DefaultResolver（系统）解析，不自行构造 DNS 报文；如果 server 是本地 127.0.0.1:53 则直接 net.LookupIP
// 后续可替换为 miekg/dns 自定义 server 解析。
func queryOne(ctx context.Context, domain, server string) []net.IP {
	var r net.Resolver
	if strings.HasPrefix(server, "127.0.0.1") || strings.HasPrefix(server, "::1") {
		ips, _ := r.LookupIP(ctx, "ip", domain)
		return ips
	}
	// 使用自定义 Dial 指定 server
	r = net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "udp", server)
	}}
	ips, _ := r.LookupIP(ctx, "ip", domain)
	return ips
}
