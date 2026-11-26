package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// Loopback has no SO_PEERCRED for TCP, but Linux lists every socket with its owner's uid in
// /proc/net/tcp. The API accepts a connection only if the client socket belongs to the same
// user (ADV-0034/0036/0037): other local users can then neither reach the API nor tie up its
// connections or rate limit. The dashboard runs the same lookup on the listening socket
// before it sends the token, so it never talks to an impostor from another account.

// procAddr encodes an IPv4 address and port as /proc/net/tcp prints them ("0100007F:223D").
func procAddr(ip net.IP, port int) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	le := []byte{v4[3], v4[2], v4[1], v4[0]}
	return strings.ToUpper(hex.EncodeToString(le)) + ":" + fmt.Sprintf("%04X", port)
}

// socketUID finds the uid owning the socket with the given local and remote addresses.
func socketUID(table io.Reader, local, remote string) (int, bool) {
	sc := bufio.NewScanner(table)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		// sl local rem st tx:rx tr:when retrnsmt uid ...
		if len(f) < 8 || f[1] != local || f[2] != remote {
			continue
		}
		uid, err := strconv.Atoi(f[7])
		return uid, err == nil
	}
	return 0, false
}

// sameUserListener drops connections from other users and caps concurrent connections.
type sameUserListener struct {
	net.Listener
	uid     int
	table   func() (io.ReadCloser, error)
	slots   chan struct{}
	refused atomic.Uint64
}

func newSameUserListener(l net.Listener, maxConns int) *sameUserListener {
	return &sameUserListener{
		Listener: l, uid: os.Getuid(), slots: make(chan struct{}, maxConns),
		table: func() (io.ReadCloser, error) { return os.Open("/proc/net/tcp") },
	}
}

func (s *sameUserListener) Accept() (net.Conn, error) {
	for {
		c, err := s.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if !s.sameUser(c) {
			s.refused.Add(1)
			_ = c.Close()
			continue
		}
		select {
		case s.slots <- struct{}{}:
			return &slotConn{Conn: c, release: func() { <-s.slots }}, nil
		default:
			_ = c.Close() // over the connection cap (same user)
			log.Printf("connection cap (%d) reached; closing new connection", cap(s.slots))
		}
	}
}

func (s *sameUserListener) sameUser(c net.Conn) bool {
	la, ok1 := c.LocalAddr().(*net.TCPAddr)
	ra, ok2 := c.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return false
	}
	t, err := s.table()
	if err != nil {
		return false // fail closed
	}
	defer t.Close()
	// The client's socket: local = its address (our remote), remote = us.
	uid, found := socketUID(t, procAddr(ra.IP, ra.Port), procAddr(la.IP, la.Port))
	return found && uid == s.uid
}

type slotConn struct {
	net.Conn
	release func()
	closed  atomic.Bool
}

func (c *slotConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}
