package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/netutil"

	"github.com/sirupsen/logrus"

	"terasu-proxy/internal/auth"
	"terasu-proxy/internal/config"
	"terasu-proxy/internal/egress"
	"terasu-proxy/internal/metrics"
	"terasu-proxy/internal/mitm"
	"terasu-proxy/internal/rules"
)

type Server struct {
	srv   *http.Server
	ln    net.Listener
	cfg   *config.Config
	log   *logrus.Logger
	rules *rules.Engine
	ca    *mitm.CA
	store *mitm.CertStore
	rp    *httputil.ReverseProxy
	auth  auth.Basic
	stats *metrics.Aggregator
}

func NewServer(cfg *config.Config, log *logrus.Logger) (*Server, error) {
	// CA
	ca, err := mitm.LoadOrCreate(cfg.CA.CertFile, cfg.CA.KeyFile, cfg.CA.AutoGenerate)
	if err != nil {
		return nil, err
	}
	store := mitm.NewCertStore(ca)

	// rules
	re := rules.New(cfg.Mode, cfg.InterceptList)

	agg := metrics.NewAggregator()

	baseTransport := egress.Transport(cfg.DNS.Mode)
	wrapped := &metrics.Transport{Base: baseTransport, Agg: agg}

	// reverse proxy using terasu transport
	rp := &httputil.ReverseProxy{
		Director: func(r *http.Request) {
			// keep original host
			if r.URL.Scheme == "" {
				r.URL.Scheme = "https"
			}
			r.Host = r.URL.Host
			r.Header.Del("Proxy-Connection")
		},
		Transport:     wrapped,
		FlushInterval: 50 * time.Millisecond,
	}

	s := &Server{cfg: cfg, log: log, rules: re, ca: ca, store: store, rp: rp,
		auth:  auth.Basic{Enabled: cfg.Security.BasicAuth.Enabled, Username: cfg.Security.BasicAuth.Username, Password: cfg.Security.BasicAuth.Password},
		stats: agg,
	}
	s.srv = &http.Server{
		Addr:           cfg.Listen,
		Handler:        http.HandlerFunc(s.handle),
		ReadTimeout:    cfg.Limits.ReadTimeout,
		WriteTimeout:   cfg.Limits.WriteTimeout,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	return s, nil
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	if s.cfg.Limits.MaxConns > 0 {
		ln = netutil.LimitListener(ln, s.cfg.Limits.MaxConns)
	}
	s.ln = ln
	s.log.Infof("listening on %s", s.cfg.Listen)
	return s.srv.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.srv.Shutdown(ctx)
}

// Stats exposes metrics aggregator for external services
func (s *Server) Stats() *metrics.Aggregator { return s.stats }

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Check(r) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"terasu-proxy\"")
		http.Error(w, "proxy auth required", http.StatusProxyAuthRequired)
		return
	}
	if r.Method == http.MethodConnect {
		s.handleConnect(w, r)
		return
	}
	// absolute-form request for proxy
	if r.URL.Host == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	s.rp.ServeHTTP(w, r)
}

func (s *Server) handleConnect(w http.ResponseWriter, r *http.Request) {
	target := r.Host
	if target == "" {
		target = r.URL.Host
	}
	if target == "" {
		http.Error(w, "bad connect", http.StatusBadRequest)
		return
	}
	if !s.rules.ShouldIntercept(target) {
		s.tunnel(w, r, target)
		return
	}
	s.mitm(w, r, target)
}

func (s *Server) tunnel(w http.ResponseWriter, r *http.Request, target string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	// dial target
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 10 * time.Second}
	serverConn, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		return
	}
	defer serverConn.Close()

	start := time.Now()
	var up, down int64 // up: client->server, down: server->client
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(serverConn, clientConn)
		up = n
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(clientConn, serverConn)
		down = n
		done <- struct{}{}
	}()
	<-done
	<-done
	// record a CONNECT event for visibility in metrics/logs
	host, _, _ := net.SplitHostPort(target)
	if host == "" {
		host = target
	}
	if s.stats != nil {
		s.stats.Add(metrics.RequestEvent{
			Ts:       time.Now().UTC(),
			Host:     host,
			Method:   http.MethodConnect,
			Path:     "/",
			Code:     200,
			Ms:       time.Since(start).Milliseconds(),
			BytesIn:  down,
			BytesOut: up,
		})
	}
}

func (s *Server) mitm(w http.ResponseWriter, r *http.Request, target string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	// write 200 first
	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")

	tlsSrv := tls.Server(clientConn, &tls.Config{
		GetCertificate: s.store.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
	})
	// serve a single connection as HTTP server
	go func() {
		httpSrv := &http.Server{Handler: s.mitmHandler(target)}
		_ = http2.ConfigureServer(httpSrv, &http2.Server{})
		_ = httpSrv.Serve(&singleUseListener{Conn: tlsSrv})
	}()
}

func (s *Server) mitmHandler(target string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// rebuild absolute URL for reverse proxy
		scheme := "https"
		if r.URL.Scheme == "" {
			r.URL.Scheme = scheme
		}
		if r.URL.Host == "" {
			r.URL.Host = target
		}
		// ensure Host preserved
		r.Host = r.URL.Host
		// remove hop-by-hop
		r.Header.Del("Proxy-Connection")
		s.rp.ServeHTTP(w, r)
	})
}

type singleUseListener struct{ Conn net.Conn }

func (l *singleUseListener) Accept() (net.Conn, error) {
	if l.Conn == nil {
		return nil, fmt.Errorf("closed")
	}
	c := l.Conn
	l.Conn = nil
	return c, nil
}
func (l *singleUseListener) Close() error   { return nil }
func (l *singleUseListener) Addr() net.Addr { return dummyAddr("mitm") }

type dummyAddr string

func (d dummyAddr) Network() string { return string(d) }
func (d dummyAddr) String() string  { return string(d) }
