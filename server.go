package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	attemptWindow = time.Minute
	maxFailures   = 5
	maxTrackedIPs = 10000
	maxBodyBytes  = 16 * 1024
)

type clientState struct {
	grantUntil  time.Time
	windowUntil time.Time
	failures    int
}

type Server struct {
	cfg     Config
	http    *http.Server
	mu      sync.Mutex
	clients map[netip.Addr]clientState
	now     func() time.Time
}

func NewServer(cfg *Config) (*Server, error) {
	if cfg == nil {
		return nil, errors.New("configuration is required")
	}
	copy := *cfg
	if err := copy.validate(); err != nil {
		return nil, err
	}
	s := &Server{cfg: copy, clients: make(map[netip.Addr]clientState), now: time.Now}
	s.http = &http.Server{Addr: copy.BindAddress, Handler: s, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	return s, nil
}

func (s *Server) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.http.Addr)
	if err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- s.http.Serve(listener) }()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := s.http.Shutdown(shutdown)
			cancel()
			if err != nil {
				_ = s.http.Close()
				return err
			}
			return nil
		case err := <-done:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ticker.C:
			s.mu.Lock()
			s.cleanup(s.now())
			s.mu.Unlock()
		}
	}
}

// Trusted peers may supply XFF. Visitor access is configured separately by trust_networks.
func trustedPeer(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsPrivate() || ip.IsLoopback()
}

func peerIP(remote string) (netip.Addr, error) {
	addr, err := netip.ParseAddrPort(remote)
	if err != nil {
		return netip.Addr{}, err
	}
	ip := addr.Addr().Unmap()
	if ip.Zone() != "" {
		return netip.Addr{}, errors.New("scoped IP addresses are not supported")
	}
	return ip, nil
}

func clientIP(r *http.Request) (netip.Addr, error) {
	peer, err := peerIP(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	if !trustedPeer(peer) {
		return peer, nil
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) == 0 {
		return peer, nil
	}
	parts := strings.Split(strings.Join(values, ","), ",")
	ips := make([]netip.Addr, len(parts))
	for i, value := range parts {
		ip, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil || ip.Zone() != "" {
			return netip.Addr{}, errors.New("invalid X-Forwarded-For")
		}
		ips[i] = ip.Unmap()
	}
	// The nearest public hop is the client boundary. Values to its left may be forged.
	for i := len(ips) - 1; i >= 0; i-- {
		if !trustedPeer(ips[i]) {
			return ips[i], nil
		}
	}
	return ips[0], nil
}

func (s *Server) cleanup(now time.Time) {
	for ip, state := range s.clients {
		if !now.Before(state.grantUntil) && !now.Before(state.windowUntil) {
			delete(s.clients, ip)
		}
	}
}

func (s *Server) isAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, network := range s.cfg.trustNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.now().Before(s.clients[ip].grantUntil)
}

// authorize holds one lock across validation and accounting so parallel failures cannot bypass the limit.
func (s *Server) authorize(ip netip.Addr, code string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	state, exists := s.clients[ip]
	if !exists && len(s.clients) >= maxTrackedIPs {
		s.cleanup(now)
		if len(s.clients) >= maxTrackedIPs {
			return http.StatusTooManyRequests
		}
	}
	if !now.Before(state.windowUntil) {
		state.failures = 0
		state.windowUntil = time.Time{}
	}
	if state.failures >= maxFailures {
		return http.StatusTooManyRequests
	}
	valid, err := totp.ValidateCustom(code, s.cfg.Secret, now, totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA512})
	if err != nil || !valid {
		if state.failures == 0 {
			state.windowUntil = now.Add(attemptWindow)
		}
		state.failures++
		s.clients[ip] = state
		return http.StatusUnauthorized
	}
	s.clients[ip] = clientState{grantUntil: now.Add(s.cfg.grantDuration)}
	return http.StatusOK
}

const formPage = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>FRP 访问授权</title><body><h1>FRP 访问授权</h1><p>输入动态验证码，允许当前 IP 在 %s 内建立连接。</p><form method="post" action="/knock"><input name="code" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required aria-label="动态验证码"><button type="submit">授权当前 IP</button></form></body></html>`

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case "/", "/knock":
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = fmt.Fprintf(w, formPage, s.cfg.grantDuration)
			return
		}
		if r.URL.Path != "/knock" || r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		s.knock(w, r)
	case "/handler":
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", 405)
			return
		}
		s.handleRPC(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) knock(w http.ResponseWriter, r *http.Request) {
	ip, err := clientIP(r)
	if err != nil {
		http.Error(w, "invalid client IP", 400)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	status := s.authorize(ip, r.PostForm.Get("code"))
	switch status {
	case http.StatusOK:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "验证成功，IP %s 已放行 %s；已有连接不会在授权到期时断开。", ip, s.cfg.grantDuration)
	case http.StatusTooManyRequests:
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many attempts; retry later", status)
	default:
		http.Error(w, "invalid authorization code", status)
	}
}

func supportedProxy(typ string) bool {
	switch typ {
	case "tcp", "https", "stcp", "tcpmux":
		return true
	}
	return false
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	ip, err := peerIP(r.RemoteAddr)
	if err != nil || !trustedPeer(ip) {
		rpcResponse(w, 403, true, "callback requires a private or loopback peer")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req struct {
		Version string          `json:"version"`
		Op      string          `json:"op"`
		Content json.RawMessage `json:"content"`
	}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		rpcResponse(w, 400, true, "invalid JSON request")
		return
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		rpcResponse(w, 400, true, "expected one JSON object")
		return
	}
	if (req.Version != "" && req.Version != "0.1.0") || len(req.Content) == 0 || string(req.Content) == "null" {
		rpcResponse(w, 400, true, "invalid plugin request")
		return
	}
	switch req.Op {
	case plugin.OpNewProxy:
		var content plugin.NewProxyContent
		if err := json.Unmarshal(req.Content, &content); err != nil || content.ProxyName == "" || content.ProxyType == "" {
			rpcResponse(w, 400, true, "invalid proxy content")
			return
		}
		if !supportedProxy(content.ProxyType) {
			rpcResponse(w, 200, true, "proxy type has no supported IP admission hook")
			return
		}
		rpcResponse(w, 200, false, "")
	case plugin.OpNewUserConn:
		var content plugin.NewUserConnContent
		if err := json.Unmarshal(req.Content, &content); err != nil || content.ProxyName == "" || content.ProxyType == "" {
			rpcResponse(w, 400, true, "invalid connection content")
			return
		}
		remote, err := peerIP(content.RemoteAddr)
		if err != nil {
			rpcResponse(w, 400, true, "invalid remote_addr")
			return
		}
		if !supportedProxy(content.ProxyType) || !s.isAllowed(remote) {
			rpcResponse(w, 200, true, "IP is not authorized")
			return
		}
		rpcResponse(w, 200, false, "")
	default:
		rpcResponse(w, 400, true, "unsupported operation")
	}
}

func rpcResponse(w http.ResponseWriter, status int, reject bool, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(plugin.Response{Reject: reject, RejectReason: reason, Unchange: !reject})
}
