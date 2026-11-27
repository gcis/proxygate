//go:build !windows

package main

import (
	"os"
	"syscall"
)

// matchOwnership gives file the owner of reference when running as root, so
// `sudo proxygate passwd` does not leave a file the service user cannot read.
func matchOwnership(reference, file string) {
	if os.Geteuid() != 0 {
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
