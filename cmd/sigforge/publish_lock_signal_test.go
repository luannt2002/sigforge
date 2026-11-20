package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// lockHelper is a publishing process that dies holding the lock: the test binary run again with
// SIGFORGE_TEST_LOCK_HELPER set to a directory. It takes the lock, says so, then waits to be killed — or, in mode
// "pipe", keeps printing to a stdout whose reader is gone, as `sigforge refresh … | head -1` does.
func lockHelper() {
	var err error
	if heldRelease, err = lockPublish(filepath.Join(os.Getenv("SIGFORGE_TEST_LOCK_HELPER"), "db.json")); err != nil {
		os.Exit(3)
	}
	os.Stdout.WriteString("locked\n")
	if os.Getenv("SIGFORGE_TEST_LOCK_MODE") == "pipe" {
		for range 1000 {
			os.Stdout.WriteString("a line nobody reads\n")
			time.Sleep(time.Millisecond)
		}
		os.Exit(5) // the broken pipe was expected to end the run
	}
	time.Sleep(time.Minute)
	os.Exit(4)
}

// heldRelease keeps the helper's lock reachable: an unreachable *os.File is closed by its finalizer, letting the lock go.
var heldRelease func()

// A run that dies holding the publish lock — killed, interrupted, terminated, or ended by a broken pipe while it
// prints — never blocks the next one: the system lets the lock go with the process, nothing to remove by hand.
func TestPublishLockFreedWhenTheRunDies(t *testing.T) {
	if os.Getenv("SIGFORGE_TEST_LOCK_HELPER") != "" {
		lockHelper()
	}
	if runtime.GOOS == "windows" {
		t.Skip("a signal cannot be sent to a process on Windows")
	}
	for _, death := range []string{"kill", "interrupt", "terminate", "pipe"} {
		dir := t.TempDir()
		cmd := exec.Command(os.Args[0], "-test.run=^TestPublishLockFreedWhenTheRunDies$")
		cmd.Env = append(os.Environ(), "SIGFORGE_TEST_LOCK_HELPER="+dir, "SIGFORGE_TEST_LOCK_MODE="+death)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if line, err := bufio.NewReader(stdout).ReadString('\n'); err != nil || line != "locked\n" {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("%s: helper said %q, %v; want locked", death, line, err)
		}
		if _, err := lockPublish(filepath.Join(dir, "db.json")); err == nil || !strings.Contains(err.Error(), "held by PID") {
			t.Errorf("%s: while the helper holds the lock a second one must be refused, got %v", death, err)
		}
		switch death {
		case "kill":
			_ = cmd.Process.Kill()
		case "interrupt":
			_ = cmd.Process.Signal(os.Interrupt)
		case "terminate":
			_ = cmd.Process.Signal(syscall.SIGTERM)
		case "pipe":
			_ = stdout.Close() // the reader of the pipe is gone
		}
		err = cmd.Wait()
		if cmd.ProcessState.ExitCode() != -1 { // -1: ended by a signal
			t.Errorf("%s: helper ended with %v, want it ended by a signal", death, err)
		}
		release, err := lockPublish(filepath.Join(dir, "db.json"))
		if err != nil {
			t.Errorf("%s: the run that held the lock is dead, yet the next one is refused: %v", death, err)
			continue
		}
		release()
	}
}
