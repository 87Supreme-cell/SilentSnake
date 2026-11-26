package main

import (
	"encoding/json"
	"time"
)

// Endpoint is an address/port pair from the capture schema (docs/api/capture-events.md).
type Endpoint struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// CaptureEvent is one line of `silentsnake.capture/1`. Body fields are flattened into the
// envelope; only the fields the API uses are decoded, and unknown fields are ignored as the
// schema requires.
type CaptureEvent struct {
	Schema  string `json:"schema"`
	Seq     uint64 `json:"seq"`
	TS      string `json:"ts"`
	Type    string `json:"type"`
	Summary string `json:"summary"`

	// engine_start
	Version string `json:"version,omitempty"`
	Source  *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"source,omitempty"`

	// flow_start / flow_end / tls_client_hello / dns
	FlowID           uint64    `json:"flow_id"`
	Proto            string    `json:"proto"`
	Direction        string    `json:"direction"`
	Initiator        *Endpoint `json:"initiator,omitempty"`
	Responder        *Endpoint `json:"responder,omitempty"`
	Service          string    `json:"service,omitempty"`
	ServerName       *string   `json:"server_name,omitempty"`
	ServerNameSource string    `json:"server_name_source,omitempty"`
	Reason           string    `json:"reason,omitempty"`
	DurationMS       uint64    `json:"duration_ms"`
	InitPackets      uint64    `json:"initiator_packets"`
	InitBytes        uint64    `json:"initiator_bytes"`
	RespPackets      uint64    `json:"responder_packets"`
	RespBytes        uint64    `json:"responder_bytes"`
	ECH              bool      `json:"ech"`
	Anomalies        []string  `json:"anomalies,omitempty"`

	// stats / engine_stop
	PacketsSeen              uint64  `json:"packets_seen"`
	BytesSeen                uint64  `json:"bytes_seen"`
	FlowsStarted             uint64  `json:"flows_started"`
	FlowsActive              uint64  `json:"flows_active"`
	UDPTrailingBytes         uint64  `json:"udp_trailing_bytes"`
	PacketsUnprocessedAtStop uint64  `json:"packets_unprocessed_at_stop"`
	KernelDropped            *uint64 `json:"kernel_dropped,omitempty"`
	InterfaceDropped         *uint64 `json:"interface_dropped,omitempty"`
}

const captureSchema = "silentsnake.capture/1"

// parseEvent decodes one JSON line. Lines from another schema are rejected.
func parseEvent(line []byte) (*CaptureEvent, time.Time, error) {
	var ev CaptureEvent
	if err := json.Unmarshal(line, &ev); err != nil {
		return nil, time.Time{}, err
	}
	if ev.Schema != captureSchema {
		return nil, time.Time{}, errSchema
	}
	ts, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		return nil, time.Time{}, err
	}
	return &ev, ts, nil
}
