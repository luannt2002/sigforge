//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || illumos || aix)

package fsio

// Without O_NOFOLLOW / O_NONBLOCK the checks around the open (Lstat before, SameFile after) carry the guarantee alone.
const (
	noFollow = 0
	nonBlock = 0
)
