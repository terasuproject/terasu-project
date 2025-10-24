package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	cfgpkg "terasu-proxy/internal/config"
	"terasu-proxy/internal/logging"
	metricspkg "terasu-proxy/internal/metrics"
	proxy "terasu-proxy/internal/proxy"
)

func main() {
	configPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	cfg, err := cfgpkg.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config error: %v\n", err)
		os.Exit(1)
	}

	log := logging.Setup(cfg.Logging.Level)
	log.Infof("starting terasu-proxy, mode=%s, listen=%s", cfg.Mode, cfg.Listen)

	p, err := proxy.NewServer(cfg, log)
	if err != nil {
		log.Fatalf("init proxy error: %v", err)
	}

	// metrics server (optional)
	var metricsSrv *http.Server
	if cfg.Metrics.Addr != "" {
		mux := metricspkg.NewMux(p.Stats())
		metricsSrv = &http.Server{
			Addr:              cfg.Metrics.Addr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
		go func() {
			log.Infof("metrics listening on %s", cfg.Metrics.Addr)
			if err := metricsSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Errorf("metrics server error: %v", err)
			}
		}()
	}

	// main proxy server
	go func() {
		if err := p.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy server error: %v", err)
		}
	}()

	// graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.Shutdown(ctx); err != nil {
		log.Errorf("shutdown proxy error: %v", err)
	}
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(ctx)
	}
}
