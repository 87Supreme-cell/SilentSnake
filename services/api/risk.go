package main

import "net"

// Risk v0: transparent, rule-based heuristics over what stage A can see (no process
// attribution yet). Every point added comes with a plain-English reason, and the score is a
// prompt to look, not a verdict. Rules are documented in docs/api/rest-api.md.

// Level bands map the 0-100 score onto the spec's four-colour scale
// (silentsnake.yaml design.color_and_accessibility.risk_scale). The label always travels
// with the colour, never colour alone.
type Level struct {
	Name  string `json:"level"`
	Color string `json:"color"`
}

func levelFor(score int) Level {
	switch {
	case score >= 75:
		return Level{"high", "red"}
	case score >= 50:
		return Level{"elevated", "orange"}
	case score >= 25:
		return Level{"guarded", "yellow"}
	default:
		return Level{"low", "green"}
	}
}

func linkLocalOrMulticast(e *Endpoint) bool {
	if e == nil {
		return false
	}
	ip := net.ParseIP(e.IP)
	return ip != nil && (ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast())
}

// FlaggedAt is the flow score from which a connection is listed as "flagged".
const FlaggedAt = 50

// plaintext services that carry credentials or content unencrypted.
var plaintext = map[uint16]string{21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP"}

func scoreFlow(f *Flow) {
	score := 0
	var reasons []string
	add := func(pts int, why string) {
		score += pts
		reasons = append(reasons, why)
	}
	// Inbound counts only for TCP/UDP from a routable peer: ICMPv6 neighbour discovery and
	// router adverts from link-local addresses are how IPv6 works, not someone connecting in
	// (false positive seen on live data, 2026-11-26).
	if f.Direction == "inbound" && (f.Proto == "tcp" || f.Proto == "udp") && !linkLocalOrMulticast(f.Initiator) {
		add(25, "another machine opened this connection to you")
	}
	if f.Direction == "transit" {
		add(10, "traffic between two other machines passed through this interface")
	}
	if f.Responder != nil && f.Direction != "local" {
		if name, ok := plaintext[f.Responder.Port]; ok && f.Proto == "tcp" {
			add(20, name+" is unencrypted")
		}
		if f.Proto == "tcp" && f.Direction == "outbound" && f.Service == "" && f.Responder.Port >= 1024 {
			add(10, "outbound TCP to an unregistered high port")
		}
	}
	for _, a := range f.TLSAnomalies {
		add(30, "TLS handshake anomaly: "+a)
	}
	if score > 100 {
		score = 100
	}
	f.Risk = score
	f.Reasons = reasons
	if score >= FlaggedAt {
		f.Status = "flagged"
	} else {
		f.Status = "allowed"
	}
}
