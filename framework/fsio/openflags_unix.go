//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || illumos || aix

package fsio

import "syscall"

// noFollow refuses a link as the last part of a path; nonBlock keeps an open from waiting on a FIFO.
const (
	noFollow = syscall.O_NOFOLLOW
	nonBlock = syscall.O_NONBLOCK
)
