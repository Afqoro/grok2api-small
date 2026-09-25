package upstream

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

// ProxyManager loads proxies from data/proxies.json and rotates them round-robin.
// Format: ["socks5://1.2.3.4:1080", "http://user:pass@5.6.7.8:8080", ...]
// Missing file = direct connection (no proxy).

type ProxyManager struct {
	proxies []string
	index   atomic.Uint64
	modTime time.Time
	mu      atomic.Pointer[time.Time]
}

var proxyMgr ProxyManager

func loadProxies() []string {
	const path = "data/proxies.json"
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if cached := proxyMgr.mu.Load(); cached != nil && cached.Equal(st.ModTime()) {
		return proxyMgr.proxies
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		slog.Warn("proxies_parse_failed", "error", err)
		return nil
	}
	modTime := st.ModTime()
	proxyMgr.mu.Store(&modTime)
	proxyMgr.proxies = list
	slog.Info("proxies_loaded", "count", len(list))
	return list
}

// NextProxy returns the next proxy URL in round-robin order, or "" for direct.
func NextProxy() string {
	list := loadProxies()
	if len(list) == 0 {
		return ""
	}
	idx := proxyMgr.index.Add(1) - 1
	return list[idx%uint64(len(list))]
}

// BuildTransport creates an http.Transport with optional proxy support.
// proxyURL can be "socks5://...", "http://...", "https://...", or "" for direct.
func BuildTransport(proxyURL string, responseHeaderTimeout time.Duration) *http.Transport {
	tr := &http.Transport{
		ResponseHeaderTimeout: responseHeaderTimeout,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: false},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	if proxyURL == "" {
		return tr
	}

	parsed, err := url.Parse(proxyURL)
	if err != nil {
		slog.Warn("proxy_parse_failed", "url", proxyURL, "error", err)
		return tr
	}

	switch parsed.Scheme {
	case "socks5", "socks5h":
		// Use DialContext to route through SOCKS5
		var auth *proxyAuth
		if parsed.User != nil {
			pass, _ := parsed.User.Password()
			auth = &proxyAuth{user: parsed.User.Username(), pass: pass}
		}
		tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialSOCKS5(ctx, parsed.Host, auth, network, addr)
		}
	case "http", "https":
		tr.Proxy = http.ProxyURL(parsed)
	default:
		slog.Warn("proxy_unknown_scheme", "url", proxyURL, "scheme", parsed.Scheme)
	}

	slog.Info("proxy_selected", "url", proxyURL, "scheme", parsed.Scheme)
	return tr
}

type proxyAuth struct {
	user string
	pass string
}

// dialSOCKS5 implements a minimal SOCKS5 client dial.
func dialSOCKS5(ctx context.Context, proxyAddr string, auth *proxyAuth, network, target string) (net.Conn, error) {
	d := net.Dialer{Timeout: 30 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	// SOCKS5 handshake
	// Version 5, 1 auth method (no auth=0x00 or user/pass=0x02)
	if auth != nil {
		conn.Write([]byte{0x05, 0x01, 0x02}) // offer user/pass
		buf := make([]byte, 2)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[0] != 0x05 || buf[1] != 0x02 {
			conn.Close()
			return nil, &net.OpError{Op: "socks5", Err: errAuthRejected}
		}
		// Send user/pass
		u := []byte(auth.user)
		p := []byte(auth.pass)
		authReq := []byte{0x01, byte(len(u))}
		authReq = append(authReq, u...)
		authReq = append(authReq, byte(len(p)))
		authReq = append(authReq, p...)
		conn.Write(authReq)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[1] != 0x00 {
			conn.Close()
			return nil, &net.OpError{Op: "socks5", Err: errAuthFailed}
		}
	} else {
		conn.Write([]byte{0x05, 0x01, 0x00}) // no auth
		buf := make([]byte, 2)
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			return nil, err
		}
		if buf[0] != 0x05 || buf[1] != 0x00 {
			conn.Close()
			return nil, &net.OpError{Op: "socks5", Err: errAuthRejected}
		}
	}

	// Connect request: CONNECT, domain or IPv4
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := net.LookupPort("tcp", portStr)
	if port < 0 || port > 65535 {
		port = 443
	}

	req := []byte{0x05, 0x01, 0x00} // CONNECT, reserved
	ip := net.ParseIP(host)
	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01) // IPv4
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04) // IPv6
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03) // domain
		req = append(req, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))

	conn.Write(req)

	resp := make([]byte, 256)
	n, err := conn.Read(resp)
	if err != nil || n < 4 {
		conn.Close()
		return nil, &net.OpError{Op: "socks5", Err: errConnectFailed}
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, &net.OpError{Op: "socks5", Err: errConnectFailed}
	}

	return conn, nil
}

var (
	errAuthRejected    = &proxyError{"socks5: auth method rejected"}
	errAuthFailed      = &proxyError{"socks5: authentication failed"}
	errConnectFailed   = &proxyError{"socks5: connect failed"}
)

type proxyError struct{ msg string }

func (e *proxyError) Error() string { return e.msg }

// Keep rand seeded
func init() {
	rand.Seed(time.Now().UnixNano())
}
