package metrics

import (
	"io"
	"net/http"
	"time"
)

type countingReadCloser struct {
	r       io.ReadCloser
	n       int64
	onClose func(total int64)
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	i, err := c.r.Read(p)
	c.n += int64(i)
	return i, err
}
func (c *countingReadCloser) Close() error {
	err := c.r.Close()
	if c.onClose != nil {
		c.onClose(c.n)
	}
	return err
}

type Transport struct {
	Base http.RoundTripper
	Agg  *Aggregator
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	start := time.Now()
	// count request body bytes actually sent to upstream if any
	var reqCount *countingReadCloser
	if req.Body != nil {
		reqCount = &countingReadCloser{r: req.Body}
		req.Body = reqCount
	}
	resp, err := base.RoundTrip(req)
	host := req.URL.Hostname()
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	if err != nil {
		// record failure quickly
		if t.Agg != nil {
			t.Agg.Add(RequestEvent{
				Ts:       time.Now().UTC(),
				Host:     host,
				Method:   req.Method,
				Path:     path,
				Code:     0,
				Ms:       time.Since(start).Milliseconds(),
				BytesIn:  0,
				BytesOut: 0,
			})
		}
		return resp, err
	}
	// wrap response body so that when client finishes reading, we emit the event with final byte counts
	if resp != nil && resp.Body != nil && t.Agg != nil {
		code := resp.StatusCode
		rb := &countingReadCloser{r: resp.Body}
		rb.onClose = func(total int64) {
			var bout int64
			if reqCount != nil {
				bout = reqCount.n
			}
			t.Agg.Add(RequestEvent{
				Ts:       time.Now().UTC(),
				Host:     host,
				Method:   req.Method,
				Path:     path,
				Code:     code,
				Ms:       time.Since(start).Milliseconds(),
				BytesIn:  total,
				BytesOut: bout,
			})
		}
		resp.Body = rb
	}
	return resp, nil
}
