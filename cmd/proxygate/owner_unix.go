//go:build !windows

package main

import (
	"os"
	"syscall"
)

// matchOwnership gives file the owner of reference when running as root, so
// `sudo proxygate passwd` does not leave a file the service user cannot read.
// geteuid is swappable so tests can exercise the root-only path.
var geteuid = os.Geteuid

func matchOwnership(reference, file string) {
	if geteuid() != 0 {
		return
	}
	info, err := os.Stat(reference)
	if err != nil {
		return
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(file, int(st.Uid), int(st.Gid))
	}
}
