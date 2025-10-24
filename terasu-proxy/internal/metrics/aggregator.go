package metrics

import (
	"sync"
	"sync/atomic"
	"time"
)

type RequestEvent struct {
	Ts       time.Time `json:"ts"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	Path     string    `json:"path"`
	Code     int       `json:"code"`
	Ms       int64     `json:"ms"`
	BytesIn  int64     `json:"bytesIn"`
	BytesOut int64     `json:"bytesOut"`
}

type hostStat struct {
	Req      uint64 `json:"req"`
	BytesIn  uint64 `json:"bytesIn"`
	BytesOut uint64 `json:"bytesOut"`
}

type Snapshot struct {
	UptimeSec     uint64              `json:"uptimeSec"`
	TotalRequests uint64              `json:"totalRequests"`
	Codes         map[int]uint64      `json:"codes"`
	BytesIn       uint64              `json:"bytesIn"`
	BytesOut      uint64              `json:"bytesOut"`
	Hosts         map[string]hostStat `json:"hosts"`
}

type Aggregator struct {
	startedAt     time.Time
	totalRequests atomic.Uint64
	bytesIn       atomic.Uint64
	bytesOut      atomic.Uint64

	mu    sync.Mutex
	codes map[int]uint64
	hosts map[string]hostStat
	buf   []RequestEvent // ring buffer for recent events to support late subscribers

	// subscribers receive events; non-blocking broadcast
	subMu sync.Mutex
	subs  map[chan RequestEvent]struct{}
}

func NewAggregator() *Aggregator {
	return &Aggregator{
		startedAt: time.Now(),
		codes:     make(map[int]uint64),
		hosts:     make(map[string]hostStat),
		buf:       make([]RequestEvent, 0, 200),
		subs:      make(map[chan RequestEvent]struct{}),
	}
}

func (a *Aggregator) Add(ev RequestEvent) {
	a.totalRequests.Add(1)
	if ev.BytesIn > 0 {
		a.bytesIn.Add(uint64(ev.BytesIn))
	}
	if ev.BytesOut > 0 {
		a.bytesOut.Add(uint64(ev.BytesOut))
	}
	a.mu.Lock()
	a.codes[ev.Code] = a.codes[ev.Code] + 1
	hs := a.hosts[ev.Host]
	hs.Req++
	if ev.BytesIn > 0 {
		hs.BytesIn += uint64(ev.BytesIn)
	}
	if ev.BytesOut > 0 {
		hs.BytesOut += uint64(ev.BytesOut)
	}
	a.hosts[ev.Host] = hs
	// append to ring buffer (keep last 200 events)
	if len(a.buf) == cap(a.buf) {
		// drop oldest by shifting slice start by 1
		a.buf = a.buf[1:]
	}
	a.buf = append(a.buf, ev)
	a.mu.Unlock()

	a.subMu.Lock()
	for ch := range a.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	a.subMu.Unlock()
}

func (a *Aggregator) Snapshot() Snapshot {
	s := Snapshot{
		UptimeSec:     uint64(time.Since(a.startedAt).Seconds()),
		TotalRequests: a.totalRequests.Load(),
		BytesIn:       a.bytesIn.Load(),
		BytesOut:      a.bytesOut.Load(),
		Codes:         make(map[int]uint64),
		Hosts:         make(map[string]hostStat),
	}
	a.mu.Lock()
	for k, v := range a.codes {
		s.Codes[k] = v
	}
	for k, v := range a.hosts {
		s.Hosts[k] = v
	}
	a.mu.Unlock()
	return s
}

func (a *Aggregator) Subscribe() (chan RequestEvent, func()) {
	ch := make(chan RequestEvent, 64)
	// take a snapshot of recent events for replay
	a.mu.Lock()
	backlog := make([]RequestEvent, len(a.buf))
	copy(backlog, a.buf)
	a.mu.Unlock()
	a.subMu.Lock()
	a.subs[ch] = struct{}{}
	a.subMu.Unlock()
	// replay backlog asynchronously without blocking
	go func() {
		for _, ev := range backlog {
			select {
			case ch <- ev:
			default:
			}
		}
	}()
	cancel := func() {
		a.subMu.Lock()
		if _, ok := a.subs[ch]; ok {
			delete(a.subs, ch)
			close(ch)
		}
		a.subMu.Unlock()
	}
	return ch, cancel
}
