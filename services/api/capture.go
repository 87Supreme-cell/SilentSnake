package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"time"
)

// maxLine bounds one capture event line; longer lines are discarded and counted.
const maxLine = 1 << 20

// staleAfter: the engine runs with --stats 1, so silence this long means it is stuck
// (stopped, wedged, or blocked) and is killed and restarted (ADV-0039). A variable for tests.
var staleAfter = 5 * time.Second

// Supervisor runs the capture engine as a child process and feeds its stdout into State and
// the Hub. The API holds no capabilities (ADV-0035): the engine gets CAP_NET_RAW from its own
// file capability. If the engine exits or goes silent, it is restarted with backoff and the
// failure is visible in /v1/overview.
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

var errStale = errors.New("no events from the capture engine for 5 s (stalled); restarting it")

func (s *Supervisor) runOnce(ctx context.Context) error {
	runCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// #nosec G204 -- the binary path is the user's own --capture-bin, checked by
	// checkExecutable; arguments are fixed apart from the validated interface name.
	cmd := exec.CommandContext(runCtx, s.Bin, "-i", s.Interface, "--stats", "1")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"} // minimal environment (ADV-0043)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr strings.Builder
	cmd.Stderr = &limitedWriter{w: &stderr, left: 4096}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start capture engine %q: %w", s.Bin, err)
	}
	s.State.Touch(time.Now())
	go s.watchdog(runCtx, cancel)
	readErr := s.consume(stdout)
	if readErr != nil {
		cancel(readErr)
	}
	err = cmd.Wait()
	if c := context.Cause(runCtx); c != nil && !errors.Is(c, context.Canceled) {
		return c
	}
	if msg := strings.TrimSpace(stderr.String()); msg != "" {
		return fmt.Errorf("capture engine: %s", msg)
	}
	return err
}

// watchdog kills the engine (via the run context) if it stops producing events.
func (s *Supervisor) watchdog(ctx context.Context, cancel context.CancelCauseFunc) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			if now.Sub(s.State.LastEventAt()) > staleAfter {
				cancel(errStale)
				return
			}
		}
	}
}

// consume reads JSON lines. A line longer than maxLine is discarded up to its newline and
// counted as rejected; reading continues (ADV-0039).
func (s *Supervisor) consume(r io.Reader) error {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			s.State.Rejected()
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		if len(line) > 0 {
			if ev, ts, perr := parseEvent(line); perr != nil {
				s.State.Rejected()
			} else {
				s.Hub.Publish(s.State.Apply(ev, ts))
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
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
