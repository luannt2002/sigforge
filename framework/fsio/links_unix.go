//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || illumos || aix

package fsio

import (
	"os"
	"syscall"
)

// linkCount is how many names the file has.
func linkCount(st os.FileInfo) (uint64, bool) {
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(s.Nlink), true
}
