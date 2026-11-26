package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"
)

// maxLine bounds one capture event line; longer lines are rejected, not buffered.
const maxLine = 1 << 20

// Supervisor runs the capture engine as a child process (it holds CAP_NET_RAW itself; this
// service holds no capabilities) and feeds its stdout into State and the Hub. If the engine
// exits, it is restarted with backoff and the failure is visible in /v1/overview.
type Supervisor struct {
	Bin       string
	Interface string
	State     *State
	Hub       *Hub
}

func (s *Supervisor) Run(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := s.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		msg := "capture engine exited"
		if err != nil {
			msg = err.Error()
		}
		s.State.EngineFailed(msg)
		log.Printf("capture: %s; restarting in %s", msg, backoff)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, time.Minute)
	}
}

func (s *Supervisor) runOnce(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, s.Bin, "-i", s.Interface, "--stats", "1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, left: 4096}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start capture engine %q: %w", s.Bin, err)
	}
	s.consume(stdout)
	err = cmd.Wait()
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("capture engine: %s", msg)
	}
	return err
}

func (s *Supervisor) consume(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), maxLine)
	for sc.Scan() {
		line := sc.Bytes()
		ev, ts, err := parseEvent(line)
		if err != nil {
			s.State.Rejected()
			continue
		}
		entry := s.State.Apply(ev, ts)
		s.Hub.Publish(entry)
	}
}

type limitedWriter struct {
	w    io.Writer
	left int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if l.left > 0 {
		k := min(n, l.left)
		_, _ = l.w.Write(p[:k])
		l.left -= k
	}
	return n, nil
}
