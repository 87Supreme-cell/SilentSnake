package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testToken = []byte(strings.Repeat("ab", 32))

func fixedNow() time.Time { return time.Date(2026, 11, 26, 18, 15, 30, 0, time.UTC) }

// Real lines from `silentsnake-capture -i lo` (2026-11-26), plus crafted inbound/TLS cases.
var sampleLines = []string{
	`{"schema":"silentsnake.capture/1","seq":1,"ts":"2026-11-26T18:15:05.172239Z","type":"engine_start","version":"0.1.0","source":{"kind":"live","name":"lo","link_type":"ethernet","euid":1000,"cap_net_raw":true},"summary":"Live capture started on interface lo with no filter."}`,
	`{"schema":"silentsnake.capture/1","seq":2,"ts":"2026-11-26T18:15:06.160208Z","type":"flow_start","flow_id":1,"proto":"udp","direction":"local","initiator":{"ip":"127.0.0.1","port":51621},"responder":{"ip":"127.0.0.1","port":9},"initiator_inferred":false,"summary":"New local UDP traffic."}`,
	`{"schema":"silentsnake.capture/1","seq":3,"ts":"2026-11-26T18:15:06.170000Z","type":"flow_start","flow_id":2,"proto":"tcp","direction":"inbound","initiator":{"ip":"203.0.113.9","port":40000},"responder":{"ip":"192.168.1.10","port":23},"initiator_inferred":false,"service":"telnet","summary":"Inbound telnet."}`,
	`{"schema":"silentsnake.capture/1","seq":4,"ts":"2026-11-26T18:15:06.180000Z","type":"flow_start","flow_id":3,"proto":"tcp","direction":"outbound","initiator":{"ip":"192.168.1.10","port":50000},"responder":{"ip":"93.184.216.34","port":443},"initiator_inferred":false,"service":"https","summary":"Outbound HTTPS."}`,
	`{"schema":"silentsnake.capture/1","seq":5,"ts":"2026-11-26T18:15:06.190000Z","type":"tls_client_hello","flow_id":3,"client":{"ip":"192.168.1.10","port":50000},"server":{"ip":"93.184.216.34","port":443},"server_name":"example.com","ech":false,"anomalies":[],"summary":"TLS to example.com."}`,
	`{"schema":"silentsnake.capture/1","seq":6,"ts":"2026-11-26T18:15:07.000000Z","type":"flow_end","flow_id":3,"proto":"tcp","direction":"outbound","initiator":{"ip":"192.168.1.10","port":50000},"responder":{"ip":"93.184.216.34","port":443},"initiator_inferred":false,"reason":"closed","duration_ms":810,"initiator_packets":5,"initiator_bytes":900,"responder_packets":6,"responder_bytes":5000,"summary":"Closed."}`,
	`{"schema":"silentsnake.capture/1","seq":7,"ts":"2026-11-26T18:15:07.172419Z","type":"stats","packets_seen":13,"bytes_seen":6246,"flows_started":3,"flows_ended":1,"udp_trailing_bytes":0,"packets_unprocessed_at_stop":0,"flows_active":2,"kernel_received":26,"kernel_dropped":0,"interface_dropped":0,"summary":"Engine health."}`,
}

func loaded(t testing.TB) (*State, *Server) {
	t.Helper()
	st := NewState("lo", fixedNow)
	for _, l := range sampleLines {
		ev, ts, err := parseEvent([]byte(l))
		if err != nil {
			t.Fatalf("parse %q: %v", l[:60], err)
		}
		st.Apply(ev, ts)
	}
	return st, NewServer(st, NewHub(), testToken, defaultPort)
}

func do(t *testing.T, s *Server, method, target, remote, host, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = remote
	r.Host = host
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

const (
	lo   = "127.0.0.1:5555"
	host = "127.0.0.1:8765"
)

func TestGuardRejections(t *testing.T) {
	_, s := loaded(t)
	tok := string(testToken)
	cases := []struct {
		name, method, target, remote, host, token string
		want                                      int
	}{
		{"ok", "GET", "/v1/health", lo, host, tok, 200},
		{"localhost host ok", "GET", "/v1/health", lo, "localhost:8765", tok, 200},
		{"non-loopback peer", "GET", "/v1/health", "10.0.0.5:5555", host, tok, 403},
		{"ipv6 loopback peer", "GET", "/v1/health", "[::1]:5555", host, tok, 403},
		{"rebinding host", "GET", "/v1/health", lo, "evil.example:8765", tok, 403},
		{"no token", "GET", "/v1/health", lo, host, "", 401},
		{"wrong token", "GET", "/v1/health", lo, host, strings.Repeat("cd", 32), 401},
		{"post", "POST", "/v1/health", lo, host, tok, 405},
		{"unknown param", "GET", "/v1/overview?x=1", lo, host, tok, 400},
		{"repeated param", "GET", "/v1/connections?limit=1&limit=2", lo, host, tok, 400},
		{"limit zero", "GET", "/v1/connections?limit=0", lo, host, tok, 400},
		{"limit huge", "GET", "/v1/connections?limit=99999999999", lo, host, tok, 400},
		{"bad state", "GET", "/v1/connections?state=x", lo, host, tok, 400},
		{"unknown path", "GET", "/v1/nope", lo, host, tok, 404},
	}
	for _, c := range cases {
		if w := do(t, s, c.method, c.target, c.remote, c.host, c.token); w.Code != c.want {
			t.Errorf("%s: got %d want %d (%s)", c.name, w.Code, c.want, w.Body.String())
		}
	}
}

func TestRateLimit(t *testing.T) {
	_, s := loaded(t)
	now := fixedNow()
	s.limiter = newTokenBucket(3, 1, func() time.Time { return now })
	for i := 0; i < 3; i++ {
		if w := do(t, s, "GET", "/v1/health", lo, host, string(testToken)); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	if w := do(t, s, "GET", "/v1/health", lo, host, string(testToken)); w.Code != 429 {
		t.Fatalf("4th request: got %d want 429", w.Code)
	}
	now = now.Add(time.Second)
	if w := do(t, s, "GET", "/v1/health", lo, host, string(testToken)); w.Code != 200 {
		t.Fatalf("after refill: %d", w.Code)
	}
}

func TestOverviewRiskAndConnections(t *testing.T) {
	_, s := loaded(t)
	w := do(t, s, "GET", "/v1/overview", lo, host, string(testToken))
	var o Overview
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatal(err)
	}
	// Inbound telnet: 25 (inbound) + 20 (plaintext) = 45 → guarded/yellow, with reasons.
	if o.Risk.Score != 45 || o.Risk.Name != "guarded" || o.Risk.Color != "yellow" {
		t.Fatalf("risk = %+v", o.Risk)
	}
	if len(o.Risk.Reasons) == 0 || !strings.Contains(o.Risk.Reasons[0], "203.0.113.9") {
		t.Fatalf("reasons = %v", o.Risk.Reasons)
	}
	if !o.Engine.Running || o.Engine.PacketsSeen != 13 || o.Engine.Incomplete || o.ActiveFlows != 2 {
		t.Fatalf("engine/flows = %+v active %d", o.Engine, o.ActiveFlows)
	}
	if len(o.TopDestinations) == 0 || o.TopDestinations[0].Name != "example.com" || o.TopDestinations[0].Bytes != 5900 {
		t.Fatalf("top = %+v", o.TopDestinations)
	}
	w = do(t, s, "GET", "/v1/connections?state=recent&limit=5", lo, host, string(testToken))
	var c struct{ Connections []Flow }
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Connections) != 1 || c.Connections[0].ServerName != "example.com" || c.Connections[0].ServerNameSource != "sni" {
		t.Fatalf("recent = %+v", c.Connections)
	}
}

func TestEngineSignalsRaiseRisk(t *testing.T) {
	st, _ := loaded(t)
	line := strings.Replace(sampleLines[6], `"udp_trailing_bytes":0`, `"udp_trailing_bytes":3`, 1)
	line = strings.Replace(line, `"kernel_dropped":0`, `"kernel_dropped":7`, 1)
	ev, ts, err := parseEvent([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	st.Apply(ev, ts)
	o := st.Overview()
	if o.Risk.Score != 100 || o.Risk.Name != "high" || !o.Engine.Incomplete {
		t.Fatalf("risk %+v incomplete %v", o.Risk, o.Engine.Incomplete)
	}
}

func TestStoppedEngineIsReported(t *testing.T) {
	st := NewState("any", fixedNow)
	st.EngineFailed("cannot start capture engine")
	o := st.Overview()
	if o.Engine.Running || o.Engine.LastError == "" || len(o.Risk.Reasons) == 0 {
		t.Fatalf("overview = %+v", o)
	}
}

func TestRejectsOtherSchemas(t *testing.T) {
	if _, _, err := parseEvent([]byte(`{"schema":"other/1","ts":"2026-11-26T18:15:05Z","type":"x"}`)); err == nil {
		t.Fatal("accepted another schema")
	}
	if _, _, err := parseEvent([]byte(`not json`)); err == nil {
		t.Fatal("accepted garbage")
	}
}

func TestListenOnlyLoopback(t *testing.T) {
	for _, bad := range []string{"0.0.0.0:8765", "[::1]:8765", "localhost:8765", "192.168.1.10:8765", "127.0.0.1:0", "127.0.0.1:+80", "127.0.0.1:99999"} {
		if _, err := loopbackPort(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if p, err := loopbackPort("127.0.0.1:8765"); err != nil || p != 8765 {
		t.Fatalf("127.0.0.1:8765: %d %v", p, err)
	}
}

func TestTokenFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "api-token")
	tok, created, err := loadOrCreateToken(path)
	if err != nil || !created || len(tok) != 64 {
		t.Fatalf("create: %v %v %d", err, created, len(tok))
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	again, created, err := loadOrCreateToken(path)
	if err != nil || created || string(again) != string(tok) {
		t.Fatalf("reload: %v %v", err, created)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(path); err == nil {
		t.Fatal("accepted a world-readable token file")
	}
}

func FuzzQueryValidation(f *testing.F) {
	for _, s := range []string{"", "limit=5", "state=active&limit=500", "limit=%zz", "a=1&a=2", "limit=-1", "limit=1e3"} {
		f.Add(s)
	}
	_, s := loaded(f)
	s.limiter = newTokenBucket(1e12, 1e12, time.Now)
	h := s.Handler()
	f.Fuzz(func(t *testing.T, raw string) {
		r := httptest.NewRequest("GET", "/v1/connections", nil)
		r.URL.RawQuery = raw
		if q, err := query(r, "state", "limit"); err == nil {
			if n, err := parseLimit(q.Get("limit"), 100); err == nil && (n < 1 || n > maxListLimit) {
				t.Fatalf("limit %d out of range for %q", n, raw)
			}
		}
		// The full handler must answer 200 or 400 with JSON, never panic or 5xx.
		r.RemoteAddr, r.Host = lo, host
		r.Header.Set("Authorization", "Bearer "+string(testToken))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 && w.Code != 400 {
			t.Fatalf("query %q: status %d", raw, w.Code)
		}
		if !json.Valid(w.Body.Bytes()) {
			t.Fatalf("query %q: invalid JSON body", raw)
		}
	})
}
