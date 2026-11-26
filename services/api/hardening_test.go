package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---- ADV-0035: privilege guard --------------------------------------------------------------

const cleanStatus = `Name:	silentsnake-api
Uid:	1000	1000	1000	1000
Gid:	1000	1000	1000	1000
Groups:	1000 10
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
`

func TestCheckPrivileges(t *testing.T) {
	if err := checkPrivileges(strings.NewReader(cleanStatus)); err != nil {
		t.Fatalf("clean status refused: %v", err)
	}
	bad := map[string][2]string{
		"ambient NET_RAW": {"CapAmb:\t0000000000000000", "CapAmb:\t0000000000002000"},
		"permitted cap":   {"CapPrm:\t0000000000000000", "CapPrm:\t0000000000200000"},
		"effective cap":   {"CapEff:\t0000000000000000", "CapEff:\t0000000000000001"},
		"inheritable cap": {"CapInh:\t0000000000000000", "CapInh:\t0000000000002000"},
		"saved uid root":  {"Uid:\t1000\t1000\t1000\t1000", "Uid:\t1000\t1000\t0\t1000"},
		"gid root":        {"Gid:\t1000\t1000\t1000\t1000", "Gid:\t1000\t0\t1000\t1000"},
		"group 0":         {"Groups:\t1000 10", "Groups:\t1000 0"},
		"missing CapAmb":  {"CapAmb:\t0000000000000000\n", ""},
	}
	for name, r := range bad {
		if err := checkPrivileges(strings.NewReader(strings.Replace(cleanStatus, r[0], r[1], 1))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCheckExecutable(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "capture")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(bin); err != nil {
		t.Fatalf("0755 binary refused: %v", err)
	}
	if err := os.Chmod(bin, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(bin); err == nil {
		t.Fatal("world-writable binary accepted")
	}
	_ = os.Chmod(bin, 0o755)
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkExecutable(bin); err == nil {
		t.Fatal("binary in a world-writable directory accepted")
	}
}

// ---- ADV-0034/0036/0037: same-user connections only ----------------------------------------

func TestProcAddrAndTable(t *testing.T) {
	if got := procAddr(net.IPv4(127, 0, 0, 1), 8765); got != "0100007F:223D" {
		t.Fatalf("procAddr = %q", got)
	}
	table := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1 1
   1: 0100007F:C350 0100007F:223D 01 00000000:00000000 00:00000000 00000000  1001        0 2 1
`
	if uid, ok := socketUID(strings.NewReader(table), "0100007F:C350", "0100007F:223D"); !ok || uid != 1001 {
		t.Fatalf("client uid = %d %v", uid, ok)
	}
	if _, ok := socketUID(strings.NewReader(table), "0100007F:0001", "0100007F:223D"); ok {
		t.Fatal("found a socket that isn't there")
	}
}

func TestSameUserListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	sl := newSameUserListener(ln, 2)
	accepted := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := sl.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	// Our own connection (same uid, real /proc/net/tcp) is accepted.
	c1, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("same-user connection was not accepted")
	}
	// A listener that expects another uid drops our connection instead of serving it.
	ln2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	other := newSameUserListener(ln2, 2)
	other.uid = os.Getuid() + 1
	go func() {
		if c, err := other.Accept(); err == nil {
			c.Close()
		}
	}()
	c2, err := net.Dial("tcp4", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	_ = c2.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("other-uid connection not closed by the server (err %v)", err)
	}
	if other.refused.Load() == 0 {
		t.Fatal("refusal not counted")
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestUnauthenticatedTrafficCannotStarveTheDashboard(t *testing.T) {
	_, s := loaded(t)
	now := fixedNow()
	s.limiter = newTokenBucket(3, 1, func() time.Time { return now })
	for i := 0; i < 50; i++ {
		if w := do(t, s, "GET", "/v1/overview", lo, host, ""); w.Code != 401 || w.Header().Get("Connection") != "close" {
			t.Fatalf("unauthenticated request %d: %d close=%q", i, w.Code, w.Header().Get("Connection"))
		}
	}
	if w := do(t, s, "GET", "/v1/overview", lo, host, string(testToken)); w.Code != 200 {
		t.Fatalf("dashboard starved: %d", w.Code)
	}
}

func TestAbsoluteFormAndEmptyParams(t *testing.T) {
	_, s := loaded(t)
	if w := do(t, s, "GET", "http://127.0.0.1:8765/v1/health", lo, host, string(testToken)); w.Code != 403 {
		t.Fatalf("absolute-form target: %d", w.Code)
	}
	for _, q := range []string{"/v1/connections?limit=", "/v1/connections?state="} {
		if w := do(t, s, "GET", q, lo, host, string(testToken)); w.Code != 400 {
			t.Errorf("%s: %d", q, w.Code)
		}
	}
}

// ---- ADV-0043: token file is checked on the open descriptor ----------------------------------

func TestTokenFileRefusesSymlinkAndFIFO(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte(strings.Repeat("ab", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "api-token")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(link); err == nil {
		t.Fatal("followed a symlinked token file")
	}
	fifo := filepath.Join(dir, "fifo-token")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := loadOrCreateToken(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("accepted a FIFO token file")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked on a FIFO token file")
	}
}

// ---- ADV-0038: the score can't be emptied by churn, restart, or time -------------------------

func applyLine(t *testing.T, st *State, line string) {
	t.Helper()
	ev, ts, err := parseEvent([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	st.Apply(ev, ts)
}

const flaggedStart = `{"schema":"silentsnake.capture/1","seq":10,"ts":"2026-11-26T18:15:06.170000Z","type":"flow_start","flow_id":77,"proto":"tcp","direction":"inbound","initiator":{"ip":"203.0.113.9","port":40000},"responder":{"ip":"192.168.1.10","port":23},"service":"telnet","summary":"x"}`

// flaggedHello adds a TLS anomaly to flow 77: 25 (inbound) + 20 (telnet) + 30 = 75, flagged.
const flaggedHello = `{"schema":"silentsnake.capture/1","seq":11,"ts":"2026-11-26T18:15:06.180000Z","type":"tls_client_hello","flow_id":77,"server_name":null,"ech":false,"anomalies":["legacy_tls_version"],"summary":"x"}`

func TestFlaggedFlowSurvivesChurn(t *testing.T) {
	st := NewState("lo", fixedNow)
	applyLine(t, st, sampleLines[0])
	applyLine(t, st, flaggedStart)
	applyLine(t, st, flaggedHello)
	applyLine(t, st, strings.Replace(strings.Replace(flaggedStart, `"type":"flow_start"`, `"type":"flow_end","reason":"closed"`, 1), `"seq":10`, `"seq":12`, 1))
	if o := st.Overview(); o.Risk.Score != 75 || o.FlaggedFlows != 1 {
		t.Fatalf("setup: %+v flagged %d", o.Risk, o.FlaggedFlows)
	}
	for i := 0; i < 2*maxRecentFlows; i++ {
		id := 1000 + i
		applyLine(t, st, strings.ReplaceAll(sampleLines[1], `"flow_id":1`, `"flow_id":`+itoa(id)))
		applyLine(t, st, strings.ReplaceAll(strings.Replace(sampleLines[1], `"type":"flow_start"`, `"type":"flow_end","reason":"idle"`, 1), `"flow_id":1`, `"flow_id":`+itoa(id)))
	}
	o := st.Overview()
	if o.Risk.Score != 75 {
		t.Fatalf("churn emptied the score: %+v", o.Risk)
	}
	found := false
	for _, c := range st.Connections("recent", maxListLimit) {
		found = found || c.ID == 77
	}
	if !found {
		t.Fatal("flagged flow no longer listed after churn")
	}
}

func TestEngineRestartKeepsEvidenceAndIsVisible(t *testing.T) {
	st, _ := loaded(t) // flow 2 (inbound telnet) is still active
	applyLine(t, st, strings.Replace(sampleLines[0], `"seq":1`, `"seq":1`, 1))
	o := st.Overview()
	if o.Engine.Restarts != 1 || o.Risk.Score < 45 {
		t.Fatalf("restart: restarts %d risk %+v", o.Engine.Restarts, o.Risk)
	}
	if !strings.Contains(strings.Join(o.Risk.Reasons, "|"), "restarted") {
		t.Fatalf("restart not explained: %v", o.Risk.Reasons)
	}
	var reason string
	for _, c := range st.Connections("recent", maxListLimit) {
		if c.ID == 2 {
			reason = c.EndReason
		}
	}
	if reason != "engine_restart" {
		t.Fatalf("open flow at restart: end_reason %q", reason)
	}
}

func TestLongOpenFlaggedFlowKeepsCounting(t *testing.T) {
	later := fixedNow().Add(2 * time.Hour)
	st := NewState("lo", func() time.Time { return later })
	applyLine(t, st, sampleLines[0])
	applyLine(t, st, flaggedStart)
	applyLine(t, st, flaggedHello)
	if o := st.Overview(); o.Risk.Score != 75 {
		t.Fatalf("open flagged flow aged out of the score: %+v", o.Risk)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// ---- ADV-0039: liveness ----------------------------------------------------------------------

func TestOverlongLineIsSkippedNotFatal(t *testing.T) {
	st := NewState("lo", time.Now)
	sup := &Supervisor{State: st, Hub: NewHub()}
	in := strings.Repeat("x", maxLine+10) + "\n" + sampleLines[0] + "\n" + sampleLines[1] + "\n"
	if err := sup.consume(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	o := st.Overview()
	if o.Engine.EventsRejected != 1 || !o.Engine.Running || o.ActiveFlows != 1 {
		t.Fatalf("after overlong line: rejected %d running %v active %d", o.Engine.EventsRejected, o.Engine.Running, o.ActiveFlows)
	}
}

func TestStalledEngineIsKilledAndReported(t *testing.T) {
	old := staleAfter
	staleAfter = 1500 * time.Millisecond
	defer func() { staleAfter = old }()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := filepath.Join(dir, "fake-capture")
	script := "#!/bin/sh\necho '" + sampleLines[0] + "'\nexec sleep 600\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	st := NewState("lo", time.Now)
	sup := &Supervisor{Bin: fake, Interface: "lo", State: st, Hub: NewHub()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	err := sup.runOnce(ctx)
	if err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Fatalf("runOnce = %v", err)
	}
	if time.Since(start) > 6*time.Second {
		t.Fatalf("stall detected too late: %s", time.Since(start))
	}
}
