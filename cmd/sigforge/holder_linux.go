//go:build linux

package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// holderPID is the PID the system reports holding a flock on f's file (/proc/locks: dev:inode matched), or "".
func holderPID(f *os.File) string {
	st, err := f.Stat()
	if err != nil {
		return ""
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	key := devKey(uint64(sys.Dev), uint64(sys.Ino))
	locks, err := os.ReadFile("/proc/locks")
	if err != nil {
		return ""
	}
	return holderIn(string(locks), key)
}

// devKey is how /proc/locks names a file: "maj:min:inode", major and minor in hex, decoded from a Linux dev_t as
// glibc lays it out — major in bits 8-19 and 44-63, minor in bits 0-7 and 20-43.
func devKey(dev, ino uint64) string {
	major := dev&0x00000000000fff00>>8 | dev&0xfffff00000000000>>32
	minor := dev&0x00000000000000ff | dev&0x00000ffffff00000>>12
	return fmt.Sprintf("%02x:%02x:%d", major, minor, ino)
}

// holderIn is the PID of the flock held on the file key ("maj:min:inode", as /proc/locks writes it) in a /proc/locks
// listing, or "". A POSIX (fcntl) lock on the same file is not the flock and is skipped, as is a waiter ("->"); a
// holder in another PID namespace is listed as 0 — no PID this run can name.
func holderIn(locks, key string) string {
	for _, line := range strings.Split(locks, "\n") {
		// "1: FLOCK  ADVISORY  WRITE 2506 103:02:7532955 0 EOF"; a waiter's line reads "1: -> FLOCK …"
		if f := strings.Fields(line); len(f) >= 6 && f[1] == "FLOCK" && f[5] == key {
			if f[4] == "0" {
				return ""
			}
			return f[4]
		}
	}
	return ""
}
