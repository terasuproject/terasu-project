package metrics

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func NewMux(agg *Aggregator) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// expose the aggregator snapshot in a stable JSON that matches GUI models
		snap := agg.Snapshot()
		_ = json.NewEncoder(w).Encode(snap)
	})
	mux.HandleFunc("/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "stream unsupported", http.StatusInternalServerError)
			return
		}
		ch, cancel := agg.Subscribe()
		defer cancel()
		notify := r.Context().Done()
		for {
			select {
			case ev, ok := <-ch:
				if !ok {
					return
				}
				b, _ := json.Marshal(ev)
				fmt.Fprintf(w, "data: %s\n\n", b)
				flusher.Flush()
			case <-notify:
				return
			case <-time.After(30 * time.Second):
				fmt.Fprint(w, ": keepalive\n\n")
				flusher.Flush()
			}
		}
	})
	return mux
}
