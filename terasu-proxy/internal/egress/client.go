package egress

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/fumiama/terasu"
	trshttp "github.com/fumiama/terasu/http"
)

var defaultDialer = net.Dialer{Timeout: 10 * time.Second}

// Transport selects transport according to dns mode.
func Transport(dnsMode string) http.RoundTripper {
	switch dnsMode {
	case "system":
		return newSystemDNSTransport()
	case "terasu", "auto":
		fallthrough
	default:
		return trshttp.DefaultClient.Transport
	}
}

// newSystemDNSTransport builds an http.Transport that resolves via system DNS
// while keeping terasu TLS handshake behavior.
func newSystemDNSTransport() http.RoundTripper {
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			addrs, err := net.DefaultResolver.LookupHost(ctx, host)
			if err != nil {
				return nil, err
			}
			var conn net.Conn
			var tlsConn *tls.Conn
			for _, a := range addrs {
				// establish TCP
				if defaultDialer.Timeout != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.Background(), defaultDialer.Timeout)
					defer cancel()
				} else if !defaultDialer.Deadline.IsZero() {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(context.Background(), defaultDialer.Deadline)
					defer cancel()
				}
				conn, err = defaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if err != nil {
					continue
				}
				tlsConn = tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
				// re-init ctx due to deadline settings in tcp dial
				if defaultDialer.Timeout != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(context.Background(), defaultDialer.Timeout)
					defer cancel()
				} else if !defaultDialer.Deadline.IsZero() {
					var cancel context.CancelFunc
					ctx, cancel = context.WithDeadline(context.Background(), defaultDialer.Deadline)
					defer cancel()
				}
				if terasu.DefaultFirstFragmentLen > 0 {
					err = terasu.Use(tlsConn).HandshakeContext(ctx, terasu.DefaultFirstFragmentLen)
				} else {
					err = tlsConn.HandshakeContext(ctx)
				}
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
				// retry with normal handshake
				conn, err = defaultDialer.DialContext(ctx, network, net.JoinHostPort(a, port))
				if err != nil {
					continue
				}
				tlsConn = tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
				err = tlsConn.HandshakeContext(ctx)
				if err == nil {
					break
				}
				_ = tlsConn.Close()
				tlsConn = nil
			}
			return tlsConn, err
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}
