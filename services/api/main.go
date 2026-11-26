// Command silentsnake-api is SilentSnake's local REST API (docs/api/rest-api.md). It runs the
// capture engine as a child process, aggregates its events, and serves them on 127.0.0.1
// only, behind a bearer token. It holds no capabilities and refuses to run as root.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	defaultPort = 8765 // silentsnake.yaml llm.providers.local.port
	maxConns    = 64   // concurrent connections (same user only; ADV-0037)
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("silentsnake-api: ")
	home, _ := os.UserHomeDir()
	bin := flag.String("capture-bin", filepath.Join(home, ".local", "bin", "silentsnake-capture"), "capture engine binary")
	iface := flag.String("interface", "any", "interface to capture on")
	listen := flag.String("listen", fmt.Sprintf("127.0.0.1:%d", defaultPort), "listen address (must be 127.0.0.1)")
	flag.Parse()

	if os.Geteuid() == 0 {
		log.Fatal("refusing to run as root")
	}
	if err := harden(); err != nil {
		log.Fatal(err)
	}
	if st, err := os.Open("/proc/self/status"); err != nil {
		log.Fatalf("cannot verify privileges: %v", err)
	} else {
		err = checkPrivileges(st)
		_ = st.Close()
		if err != nil {
			log.Fatal(err)
		}
	}
	if err := checkExecutable(*bin); err != nil {
		log.Fatal(err)
	}
	port, err := loopbackPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	if strings.ContainsAny(*iface, " \t\n/") || *iface == "" || len(*iface) > 64 {
		log.Fatal("invalid --interface")
	}
	dir, err := configDir()
	if err != nil {
		log.Fatal(err)
	}
	token, created, err := loadOrCreateToken(filepath.Join(dir, "api-token"))
	if err != nil {
		log.Fatal(err)
	}
	if created {
		log.Printf("created API token in %s (mode 0600)", filepath.Join(dir, "api-token"))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state := NewState(*iface, time.Now)
	hub := NewHub()
	go (&Supervisor{Bin: *bin, Interface: *iface, State: state, Hub: hub}).Run(ctx)

	ln, err := net.Listen("tcp4", *listen)
	if err != nil {
		log.Fatal(err)
	}
	handler := NewServer(state, hub, token, port).Handler()
	// Hold [::1]:port too, so nobody can squat it for clients that resolve "localhost" to
	// IPv6 (ADV-0034). It serves the same handler, which refuses every non-127.0.0.1 peer.
	if ln6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", port)); err == nil {
		srv6 := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 10 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
		go func() { _ = srv6.Serve(newSameUserListener(ln6, 8)) }()
	} else {
		log.Printf("note: cannot hold [::1]:%d (%v); clients must use 127.0.0.1", port, err)
	}
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Printf("listening on http://%s (capture: %s on %s)", *listen, *bin, *iface)
	if err := srv.Serve(newSameUserListener(ln, maxConns)); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// loopbackPort accepts only 127.0.0.1:<port> (CLAUDE.md section 4: bind 127.0.0.1 only).
func loopbackPort(addr string) (int, error) {
	host, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("invalid --listen %q: %w", addr, err)
	}
	if host != "127.0.0.1" {
		return 0, fmt.Errorf("refusing to listen on %q: only 127.0.0.1 is allowed", host)
	}
	var port int
	if _, err := fmt.Sscanf(p, "%d", &port); err != nil || port < 1 || port > 65535 || fmt.Sprint(port) != p {
		return 0, fmt.Errorf("invalid port %q", p)
	}
	return port, nil
}

// configDir returns $XDG_DATA_HOME/silentsnake/config (default ~/.local/share/...), creating
// it 0700 if needed and refusing to use it if it or its parent is looser than 0700.
func configDir() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" || !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		base = filepath.Join(home, ".local", "share")
	}
	root := filepath.Join(base, "silentsnake")
	dir := filepath.Join(root, "config")
	// #nosec G703 -- the user's own data dir ($XDG_DATA_HOME, absolute); every component's
	// owner and mode are verified below.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, d := range []string{root, dir} {
		if err := private(d, true); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// private checks that path is owned by us and has no group/other permissions.
func private(path string, isDir bool) error {
	fi, err := os.Lstat(path) // #nosec G703 -- our own data dir; this is the check itself
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink != 0 || fi.IsDir() != isDir {
		return fmt.Errorf("%s: unexpected file type", path)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: not owned by the current user", path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s: permissions %o are looser than 0700/0600; refusing to start", path, fi.Mode().Perm())
	}
	return nil
}

// loadOrCreateToken reads the 64-hex-char token, or creates one (32 random bytes) with 0600.
// The file is opened without following symlinks and without blocking, and its type, owner
// and mode are checked on the open descriptor before anything is read (ADV-0043).
func loadOrCreateToken(path string) ([]byte, bool, error) {
	// #nosec G304 -- fixed path in our 0700 data dir; no symlinks, checked on the open fd.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err == nil {
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			return nil, false, err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		switch {
		case !fi.Mode().IsRegular():
			return nil, false, fmt.Errorf("%s: not a regular file", path)
		case !ok || int(st.Uid) != os.Getuid():
			return nil, false, fmt.Errorf("%s: not owned by the current user", path)
		case fi.Mode().Perm()&0o077 != 0:
			return nil, false, fmt.Errorf("%s: permissions %o are looser than 0600; refusing to start", path, fi.Mode().Perm())
		}
		b, err := io.ReadAll(io.LimitReader(f, 256))
		if err != nil {
			return nil, false, err
		}
		t := strings.TrimSpace(string(b))
		if _, err := hex.DecodeString(t); err != nil || len(t) != 64 {
			return nil, false, fmt.Errorf("%s: malformed token; delete it to create a new one", path)
		}
		return []byte(t), false, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, false, err
	}
	t := hex.EncodeToString(raw)
	// #nosec G304 -- fixed path in our 0700 data dir; O_EXCL|O_NOFOLLOW create.
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, false, err
	}
	if _, err := w.WriteString(t + "\n"); err != nil {
		_ = w.Close()
		return nil, false, err
	}
	if err := w.Close(); err != nil {
		return nil, false, err
	}
	return []byte(t), true, nil
}
