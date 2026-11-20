//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// openLock opens the lock file for locking only: created by this run — O_CREATE|O_EXCL fails on any existing path, a
// symbolic link included, so it never creates through one — or opened as it is without following a symbolic link or
// waiting on a FIFO. created says this run made it.
func openLock(path string) (f *os.File, created bool, err error) {
	f, err = os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		return f, true, nil
	}
	if errors.Is(err, fs.ErrExist) {
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if errors.Is(err, syscall.ELOOP) {
		err = fmt.Errorf("%s is a symbolic link, never followed", path)
	}
	return f, false, err
}

// tryLock takes an exclusive flock on f without waiting; held reports that another open of the file has it. The
// system drops the lock when the descriptor closes — or the process ends, however it ends.
func tryLock(f *os.File) (held bool, err error) {
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return true, nil
	}
	return false, err
}
