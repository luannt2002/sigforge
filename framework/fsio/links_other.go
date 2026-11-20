//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || illumos || aix)

package fsio

import "os"

// linkCount is unknown here: the file's information carries no count of its names on this system.
func linkCount(os.FileInfo) (uint64, bool) { return 0, false }
