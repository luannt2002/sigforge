//go:build windows

package main

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe" // fsio-exempt import(unsafe): the address of the OVERLAPPED struct LockFileEx takes
)

// openLock opens the lock file for locking only: created by this run, or opened as it is. created says this run made
// it. Windows follows a symbolic link here; nothing is written through it.
func openLock(path string) (f *os.File, created bool, err error) {
	// fsio-exempt os.OpenFile: a fresh lock target (O_EXCL), never read or written
	f, err = os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err == nil {
		return f, true, nil
	}
	if errors.Is(err, fs.ErrExist) {
		// fsio-exempt os.OpenFile: a lock target only, never read or written; Windows has no O_NOFOLLOW
		f, err = os.OpenFile(path, os.O_RDONLY, 0)
	}
	return f, false, err
}

// kernel32.dll is a KnownDLL: Windows loads it from the system directory only, never from one a user can write.
// fsio-exempt syscall.NewLazyDLL: a KnownDLL, loaded from the system directory only
var kernel32 = syscall.NewLazyDLL("kernel32.dll")

// fsio-exempt (*syscall.LazyDLL).NewProc: the system's lock call, from kernel32.dll
var procLockFileEx = kernel32.NewProc("LockFileEx")

const (
	lockfileFailImmediately = 0x1
	lockfileExclusiveLock   = 0x2
	errorLockViolation      = syscall.Errno(33)
)

// tryLock takes an exclusive lock on one byte of f, past its content, without waiting (LockFileEx); held reports that
// another handle has it. Windows drops the lock when the
// handle closes or the process ends — after a process dies, "as soon as system resources allow", so a run right
// after may still be refused once. Built, not tested, on Windows.
func tryLock(f *os.File) (held bool, err error) {
	ol := syscall.Overlapped{OffsetHigh: 0x7fffffff} // locking past the end of the file is allowed
	// fsio-exempt (*syscall.LazyProc).Call: LockFileEx on the lock file this run opened
	r, _, e := procLockFileEx.Call(f.Fd(), lockfileExclusiveLock|lockfileFailImmediately, 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return false, nil
	}
	if errors.Is(e, errorLockViolation) {
		return true, nil
	}
	return false, e
}
