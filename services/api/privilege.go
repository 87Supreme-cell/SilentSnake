package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
)

// checkPrivileges refuses to run with any privilege (ADV-0035, Ronin's decision 2026-11-26:
// the API holds no capabilities; the capture binary gets CAP_NET_RAW from its own file
// capability). It fails closed: root in any uid/gid slot, root in the supplementary groups,
// or any bit in the inheritable, permitted, effective or ambient capability sets.
func checkPrivileges(status io.Reader) error {
	seen := map[string]bool{}
	sc := bufio.NewScanner(status)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch key {
		case "Uid", "Gid":
			f := strings.Fields(val)
			if len(f) != 4 {
				return fmt.Errorf("cannot parse %s line", key)
			}
			for _, id := range f {
				if id == "0" {
					return fmt.Errorf("refusing to run with %s 0 (root) in any slot", strings.ToLower(key))
				}
			}
			seen[key] = true
		case "Groups":
			for _, g := range strings.Fields(val) {
				if g == "0" {
					return fmt.Errorf("refusing to run as a member of group 0 (root)")
				}
			}
			seen[key] = true
		case "CapInh", "CapPrm", "CapEff", "CapAmb":
			if strings.Trim(val, "0") != "" {
				return fmt.Errorf("refusing to run with capabilities (%s %s): the API needs none; "+
					"only the capture binary holds CAP_NET_RAW", key, val)
			}
			seen[key] = true
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	for _, k := range []string{"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapAmb"} {
		if !seen[k] {
			return fmt.Errorf("cannot verify privileges: no %s in /proc/self/status", k)
		}
	}
	return nil
}

// harden keeps the token out of core dumps and other users' reach (ADV-0043).
func harden() error {
	const prSetDumpable = 4
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %v", e)
	}
	return syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})
}

// checkExecutable refuses a capture binary (or its directory) that someone other than this
// user or root could modify (ADV-0043).
func checkExecutable(path string) error {
	for _, p := range []string{path, dirOf(path)} {
		fi, err := os.Stat(p)
		if err != nil {
			return fmt.Errorf("capture binary: %w", err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("capture binary: cannot stat %s", p)
		}
		if int(st.Uid) != os.Getuid() && st.Uid != 0 {
			return fmt.Errorf("capture binary: %s is owned by uid %d, not you or root", p, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("capture binary: %s is writable by group or others (mode %o)", p, fi.Mode().Perm())
		}
	}
	return nil
}

func dirOf(p string) string {
	if i := strings.LastIndexByte(p, '/'); i > 0 {
		return p[:i]
	}
	return "."
}
