//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || windows)

package main

import (
	"errors"
	"io/fs"
	"os"

	"github.com/luannt2002/sigforge/framework/fsio"
)

// openLock opens the lock file: created by this run, or opened as it is. created says this run made it.
func openLock(path string) (f *os.File, created bool, err error) {
	// fsio-exempt os.OpenFile: a fresh lock target (O_EXCL), never read or written
	f, err = os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		return f, true, nil
	}
	if errors.Is(err, fs.ErrExist) {
		// fsio-exempt fsio.OpenOwn: the lock target as it is — a link refused, never followed; a FIFO never waited on
		f, err = fsio.OpenOwn(path)
	}
	return f, false, err
}

// tryLock takes no lock on a system with neither flock nor LockFileEx: publishes there are not serialized
// (docs/snapshot-governance.md §5).
func tryLock(*os.File) (held bool, err error) { return false, nil }
