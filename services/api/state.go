package main

import (
	"errors"
	"sort"
	"sync"
	"time"
)

var errSchema = errors.New("not a silentsnake.capture/1 event")

const (
	maxRecentFlows  = 500
	maxRecentEvents = 500
	trafficMinutes  = 60
	// Engine-level findings count toward the overall score for this long.
	engineSignalTTL = 10 * time.Minute
	// Overall risk considers flows seen within this window.
	riskWindow = 5 * time.Minute
)

// Flow is one connection as the dashboard sees it.
type Flow struct {
	ID               uint64    `json:"flow_id"`
	Proto            string    `json:"proto"`
	Direction        string    `json:"direction"`
	Initiator        *Endpoint `json:"initiator"`
	Responder        *Endpoint `json:"responder"`
	Service          string    `json:"service,omitempty"`
	ServerName       string    `json:"server_name,omitempty"`
	ServerNameSource string    `json:"server_name_source,omitempty"`
	Started          time.Time `json:"started"`
	LastSeen         time.Time `json:"last_seen"`
	Ended            bool      `json:"ended"`
	EndReason        string    `json:"end_reason,omitempty"`
	BytesOut         uint64    `json:"initiator_bytes"`
	BytesIn          uint64    `json:"responder_bytes"`
	TLSAnomalies     []string  `json:"tls_anomalies,omitempty"`
	Risk             int       `json:"risk"`
	Reasons          []string  `json:"risk_reasons,omitempty"`
	Status           string    `json:"status"` // allowed | flagged (stage A never blocks)
	Summary          string    `json:"summary"`
}

// LogEntry is one capture event for the live log panel.
type LogEntry struct {
	Seq     uint64    `json:"seq"`
	TS      time.Time `json:"ts"`
	Type    string    `json:"type"`
	Summary string    `json:"summary"`
	FlowID  uint64    `json:"flow_id,omitempty"`
}

type minuteBucket struct {
	Minute time.Time `json:"minute"`
	Bytes  uint64    `json:"bytes"`
	Flows  uint64    `json:"flows"`
}

// Engine describes the capture subprocess.
type Engine struct {
	Running        bool      `json:"running"`
	Interface      string    `json:"interface"`
	Version        string    `json:"version,omitempty"`
	StartedAt      time.Time `json:"started_at,omitempty"`
	PacketsSeen    uint64    `json:"packets_seen"`
	BytesSeen      uint64    `json:"bytes_seen"`
	FlowsActive    uint64    `json:"flows_active"`
	KernelDropped  uint64    `json:"kernel_dropped"`
	Incomplete     bool      `json:"incomplete"`
	LastError      string    `json:"last_error,omitempty"`
	EventsRejected uint64    `json:"events_rejected"`
}

// State aggregates the capture stream. All methods are safe for concurrent use.
type State struct {
	mu        sync.Mutex
	now       func() time.Time
	engine    Engine
	active    map[uint64]*Flow
	recent    []*Flow // ended, newest last
	events    []LogEntry
	buckets   []minuteBucket
	lastBytes uint64
	lastFlows uint64
	// Engine-level signals that raise the overall score.
	lastTrailing   uint64
	trailingSeenAt time.Time
	droppedSeenAt  time.Time
}

func NewState(iface string, now func() time.Time) *State {
	return &State{now: now, active: map[uint64]*Flow{}, engine: Engine{Interface: iface}}
}

func endpointCopy(e *Endpoint) *Endpoint {
	if e == nil {
		return nil
	}
	c := *e
	return &c
}

// Apply folds one event into the state and returns the live-log entry for it.
func (s *State) Apply(ev *CaptureEvent, ts time.Time) LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := LogEntry{Seq: ev.Seq, TS: ts, Type: ev.Type, Summary: ev.Summary, FlowID: ev.FlowID}
	switch ev.Type {
	case "engine_start":
		s.engine.Running = true
		s.engine.Version = ev.Version
		s.engine.StartedAt = ts
		s.engine.LastError = ""
		s.active = map[uint64]*Flow{}
		s.lastBytes, s.lastFlows, s.lastTrailing = 0, 0, 0
	case "flow_start":
		f := &Flow{
			ID: ev.FlowID, Proto: ev.Proto, Direction: ev.Direction,
			Initiator: endpointCopy(ev.Initiator), Responder: endpointCopy(ev.Responder),
			Service: ev.Service, ServerNameSource: ev.ServerNameSource,
			Started: ts, LastSeen: ts, Summary: ev.Summary,
		}
		if ev.ServerName != nil {
			f.ServerName = *ev.ServerName
		}
		scoreFlow(f)
		s.active[f.ID] = f
	case "tls_client_hello":
		if f := s.active[ev.FlowID]; f != nil {
			if ev.ServerName != nil && *ev.ServerName != "" {
				f.ServerName, f.ServerNameSource = *ev.ServerName, "sni"
			}
			f.TLSAnomalies = append(f.TLSAnomalies, ev.Anomalies...)
			f.LastSeen = ts
			scoreFlow(f)
		}
	case "flow_end":
		f := s.active[ev.FlowID]
		if f == nil { // started before we attached
			f = &Flow{ID: ev.FlowID, Proto: ev.Proto, Direction: ev.Direction,
				Initiator: endpointCopy(ev.Initiator), Responder: endpointCopy(ev.Responder),
				Service: ev.Service, Started: ts.Add(-time.Duration(ev.DurationMS) * time.Millisecond)}
			if ev.ServerName != nil {
				f.ServerName = *ev.ServerName
			}
			scoreFlow(f)
		}
		delete(s.active, ev.FlowID)
		f.Ended, f.EndReason, f.LastSeen = true, ev.Reason, ts
		f.BytesOut, f.BytesIn = ev.InitBytes, ev.RespBytes
		f.Summary = ev.Summary
		s.recent = append(s.recent, f)
		if len(s.recent) > maxRecentFlows {
			s.recent = s.recent[len(s.recent)-maxRecentFlows:]
		}
	case "stats", "engine_stop":
		s.applyCounters(ev, ts)
		if ev.Type == "engine_stop" {
			s.engine.Running = false
		}
	}
	s.events = append(s.events, entry)
	if len(s.events) > maxRecentEvents {
		s.events = s.events[len(s.events)-maxRecentEvents:]
	}
	return entry
}

func (s *State) applyCounters(ev *CaptureEvent, ts time.Time) {
	e := &s.engine
	e.PacketsSeen, e.BytesSeen, e.FlowsActive = ev.PacketsSeen, ev.BytesSeen, ev.FlowsActive
	var dropped uint64
	if ev.KernelDropped != nil {
		dropped += *ev.KernelDropped
	}
	if ev.InterfaceDropped != nil {
		dropped += *ev.InterfaceDropped
	}
	if dropped > e.KernelDropped {
		s.droppedSeenAt = ts
	}
	e.KernelDropped = dropped
	e.Incomplete = dropped > 0 || ev.PacketsUnprocessedAtStop > 0
	if ev.UDPTrailingBytes > s.lastTrailing {
		s.trailingSeenAt = ts
	}
	s.lastTrailing = ev.UDPTrailingBytes

	// Per-minute traffic from counter deltas (counters only grow within one engine run).
	db, df := ev.BytesSeen-min(ev.BytesSeen, s.lastBytes), ev.FlowsStarted-min(ev.FlowsStarted, s.lastFlows)
	s.lastBytes, s.lastFlows = ev.BytesSeen, ev.FlowsStarted
	m := ts.Truncate(time.Minute)
	if n := len(s.buckets); n > 0 && s.buckets[n-1].Minute.Equal(m) {
		s.buckets[n-1].Bytes += db
		s.buckets[n-1].Flows += df
	} else {
		s.buckets = append(s.buckets, minuteBucket{Minute: m, Bytes: db, Flows: df})
		if len(s.buckets) > trafficMinutes {
			s.buckets = s.buckets[len(s.buckets)-trafficMinutes:]
		}
	}
}

// EngineFailed records that the capture process exited or could not start.
func (s *State) EngineFailed(msg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.engine.Running = false
	s.engine.LastError = msg
}

// Rejected counts an output line that was not a valid capture event.
func (s *State) Rejected() {
	s.mu.Lock()
	s.engine.EventsRejected++
	s.mu.Unlock()
}

type Risk struct {
	Score int `json:"score"`
	Level
	Reasons []string `json:"reasons"`
}

type Destination struct {
	Name  string `json:"name"`
	Bytes uint64 `json:"bytes"`
	Flows int    `json:"flows"`
}

type Overview struct {
	Risk            Risk           `json:"risk"`
	Engine          Engine         `json:"engine"`
	ActiveFlows     int            `json:"active_flows"`
	FlaggedFlows    int            `json:"flagged_flows"`
	Traffic         []minuteBucket `json:"traffic_per_minute"`
	TopDestinations []Destination  `json:"top_destinations"`
	GeneratedAt     time.Time      `json:"generated_at"`
}

// destName is the other end of the connection as the user thinks of it: the named server
// for outbound traffic, the remote initiator for inbound traffic (the responder is us).
func destName(f *Flow) string {
	if f.Direction == "inbound" && f.Initiator != nil {
		return f.Initiator.IP
	}
	if f.ServerName != "" {
		return f.ServerName
	}
	if f.Responder != nil {
		return f.Responder.IP
	}
	return "unknown"
}

func (s *State) Overview() Overview {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	o := Overview{Engine: s.engine, ActiveFlows: len(s.active), GeneratedAt: now}
	o.Traffic = append([]minuteBucket{}, s.buckets...)

	// Overall risk: the riskiest flow seen within riskWindow, plus engine-level signals.
	top := 0
	var reasons []string
	dest := map[string]*Destination{}
	consider := func(f *Flow) {
		if f.Status == "flagged" {
			o.FlaggedFlows++
		}
		if now.Sub(f.LastSeen) <= riskWindow && f.Risk > top {
			top = f.Risk
			reasons = append([]string{}, f.Reasons...)
			if len(reasons) > 0 {
				reasons[0] = destName(f) + ": " + reasons[0]
			}
		}
		d := dest[destName(f)]
		if d == nil {
			d = &Destination{Name: destName(f)}
			dest[d.Name] = d
		}
		d.Bytes += f.BytesOut + f.BytesIn
		d.Flows++
	}
	for _, f := range s.active {
		consider(f)
	}
	for _, f := range s.recent {
		consider(f)
	}
	score := top
	if !s.trailingSeenAt.IsZero() && now.Sub(s.trailingSeenAt) <= engineSignalTTL {
		score += 40
		reasons = append(reasons, "UDP datagrams with hidden trailing bytes were seen (a known evasion trick)")
	}
	if !s.droppedSeenAt.IsZero() && now.Sub(s.droppedSeenAt) <= engineSignalTTL {
		score += 15
		reasons = append(reasons, "the capture dropped packets, so the record is incomplete")
	}
	if !s.engine.Running {
		reasons = append(reasons, "the capture engine is not running, so nothing is being monitored")
	}
	if score > 100 {
		score = 100
	}
	if reasons == nil {
		reasons = []string{}
	}
	o.Risk = Risk{Score: score, Level: levelFor(score), Reasons: reasons}

	for _, d := range dest {
		o.TopDestinations = append(o.TopDestinations, *d)
	}
	sort.Slice(o.TopDestinations, func(i, j int) bool {
		a, b := o.TopDestinations[i], o.TopDestinations[j]
		if a.Bytes != b.Bytes {
			return a.Bytes > b.Bytes
		}
		return a.Name < b.Name
	})
	if len(o.TopDestinations) > 10 {
		o.TopDestinations = o.TopDestinations[:10]
	}
	return o
}

// Connections returns active flows (newest first), then recently ended ones, up to limit.
func (s *State) Connections(state string, limit int) []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Flow
	if state == "active" || state == "all" {
		act := make([]*Flow, 0, len(s.active))
		for _, f := range s.active {
			act = append(act, f)
		}
		sort.Slice(act, func(i, j int) bool { return act[i].LastSeen.After(act[j].LastSeen) })
		for _, f := range act {
			out = append(out, *f)
		}
	}
	if state == "recent" || state == "all" {
		for i := len(s.recent) - 1; i >= 0; i-- {
			out = append(out, *s.recent[i])
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	if out == nil {
		out = []Flow{}
	}
	return out
}

func (s *State) Events(limit int) []LogEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := min(limit, len(s.events))
	out := make([]LogEntry, n)
	copy(out, s.events[len(s.events)-n:])
	return out
}
