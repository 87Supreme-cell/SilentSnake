package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxStreams   = 4
	rateBurst    = 40
	ratePerSec   = 20
	maxListLimit = 500
	// streamWriteTimeout: a stream client that can't take an event this fast is dropped.
	streamWriteTimeout = 5 * time.Second
)

// Server is the local REST API (docs/api/rest-api.md): GET only, 127.0.0.1 only,
// bearer-token auth, strict query validation, a global rate limit.
type Server struct {
	State   *State
	Hub     *Hub
	Token   []byte
	Port    int
	streams chan struct{}
	limiter *tokenBucket
}

func NewServer(st *State, hub *Hub, token []byte, port int) *Server {
	return &Server{State: st, Hub: hub, Token: token, Port: port,
		streams: make(chan struct{}, maxStreams),
		limiter: newTokenBucket(rateBurst, ratePerSec, time.Now)}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/overview", s.overview)
	mux.HandleFunc("GET /v1/connections", s.connections)
	mux.HandleFunc("GET /v1/events", s.events)
	mux.HandleFunc("GET /v1/stream", s.stream)
	return s.guard(mux)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// guard applies, in order: loopback peer, Host header (DNS-rebinding defence), method,
// rate limit, bearer token. Every rejection is a plain JSON error with no detail on the token.
func (s *Server) guard(next http.Handler) http.Handler {
	hosts := map[string]bool{
		fmt.Sprintf("127.0.0.1:%d", s.Port): true,
		fmt.Sprintf("localhost:%d", s.Port): true,
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// Every rejection before authentication closes the connection, so nothing
		// unauthenticated can hold a keep-alive slot (ADV-0037).
		reject := func(code int, msg string) {
			h.Set("Connection", "close")
			fail(w, code, msg)
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() || ip.To4() == nil {
			reject(http.StatusForbidden, "only 127.0.0.1 may connect")
			return
		}
		// Origin-form targets only: an absolute-form target would override Host (ADV-0044).
		if !strings.HasPrefix(r.RequestURI, "/") || !hosts[r.Host] {
			reject(http.StatusForbidden, "unexpected Host header or request target")
			return
		}
		if r.Method != http.MethodGet {
			h.Set("Allow", "GET")
			reject(http.StatusMethodNotAllowed, "read-only API: GET only")
			return
		}
		const prefix = "Bearer "
		auth := r.Header.Get("Authorization")
		if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix ||
			subtle.ConstantTimeCompare([]byte(auth[len(prefix):]), s.Token) != 1 {
			h.Set("WWW-Authenticate", `Bearer realm="silentsnake"`)
			reject(http.StatusUnauthorized, "missing or invalid token")
			return
		}
		// The rate limit applies to authenticated clients only, so unauthenticated traffic
		// can't starve the dashboard (ADV-0036).
		if !s.limiter.Allow() {
			h.Set("Retry-After", "1")
			fail(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// query validates that only the allowed parameters are present, each at most once.
func query(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("malformed query")
	}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for k, v := range q {
		if !ok[k] {
			return nil, fmt.Errorf("unknown parameter %q", truncate(k, 32))
		}
		if len(v) != 1 {
			return nil, fmt.Errorf("parameter %q given more than once", k)
		}
		if v[0] == "" {
			return nil, fmt.Errorf("parameter %q is empty", k)
		}
	}
	return q, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// parseLimit accepts a decimal integer in [1, maxListLimit]; absent means def.
func parseLimit(v string, def int) (int, error) {
	if v == "" {
		return def, nil
	}
	if len(v) > 4 {
		return 0, fmt.Errorf("limit must be between 1 and %d", maxListLimit)
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxListLimit {
		return 0, fmt.Errorf("limit must be between 1 and %d", maxListLimit)
	}
	return n, nil
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	if _, err := query(r); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "api": "silentsnake.api/1"})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	if _, err := query(r); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.State.Overview())
}

func (s *Server) connections(w http.ResponseWriter, r *http.Request) {
	q, err := query(r, "state", "limit")
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	state := q.Get("state")
	switch state {
	case "":
		state = "all"
	case "active", "recent", "all":
	default:
		fail(w, http.StatusBadRequest, "state must be active, recent or all")
		return
	}
	limit, err := parseLimit(q.Get("limit"), 100)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"connections": s.State.Connections(state, limit)})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	q, err := query(r, "limit")
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, err := parseLimit(q.Get("limit"), 100)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": s.State.Events(limit)})
}

// stream is Server-Sent Events: `event: log` per capture event, `event: overview` every
// second. At most maxStreams at once.
func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	if _, err := query(r); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	select {
	case s.streams <- struct{}{}:
		defer func() { <-s.streams }()
	default:
		fail(w, http.StatusTooManyRequests, "too many open streams")
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	sub := s.Hub.Subscribe()
	defer s.Hub.Unsubscribe(sub)
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var wmu sync.Mutex
	send := func(event string, v any) bool {
		b, err := json.Marshal(v)
		if err != nil {
			return false
		}
		wmu.Lock()
		defer wmu.Unlock()
		// A client that stops reading loses its slot instead of holding it forever (ADV-0041).
		if err := rc.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send("overview", s.State.Overview()) {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case e := <-sub.C:
			if !send("log", e) {
				return
			}
		case <-tick.C:
			o := s.State.Overview()
			if !send("overview", struct {
				Overview
				StreamDropped uint64 `json:"stream_dropped"`
			}{o, sub.Dropped.Load()}) {
				return
			}
		}
	}
}

// tokenBucket is a small global rate limiter.
type tokenBucket struct {
	mu     sync.Mutex
	tokens float64
	max    float64
	rate   float64
	last   time.Time
	now    func() time.Time
}

func newTokenBucket(burst, perSec float64, now func() time.Time) *tokenBucket {
	return &tokenBucket{tokens: burst, max: burst, rate: perSec, last: now(), now: now}
}

func (b *tokenBucket) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	t := b.now()
	b.tokens = min(b.max, b.tokens+t.Sub(b.last).Seconds()*b.rate)
	b.last = t
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
