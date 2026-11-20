package main

import "testing"

// The holder named is the one holding the flock on that very file: a POSIX lock on the same file, a waiter, and a flock
// on another file are not it.
func TestHolderIsTheFlockOnThatFile(t *testing.T) {
	const locks = `1: POSIX  ADVISORY  WRITE 1111 103:02:777 0 EOF
2: FLOCK  ADVISORY  WRITE 2222 103:02:888 0 EOF
3: -> FLOCK  ADVISORY  WRITE 3333 103:02:777 0 EOF
4: FLOCK  ADVISORY  WRITE 4444 103:02:777 0 EOF
5: FLOCK  ADVISORY  WRITE 6666 103:02:666
6: FLOCK  ADVISORY  WRITE 7777
7: FLOCK  ADVISORY  WRITE 0 103:02:555 0 EOF
`
	if got := holderIn(locks, "103:02:777"); got != "4444" {
		t.Errorf("holder of 103:02:777 = %q, want 4444 (its flock), not the POSIX lock 1111 nor the waiter 3333", got)
	}
	if got := holderIn(locks, "103:02:666"); got != "6666" { // the fields a holder needs, no range after them
		t.Errorf("holder of 103:02:666 = %q, want 6666", got)
	}
	if got := holderIn(locks, "103:02:555"); got != "" { // a holder in another PID namespace
		t.Errorf("holder listed as PID 0 = %q, want none named", got)
	}
	if got := holderIn(locks, "103:02:999"); got != "" { // and a cut-off line is skipped, not read past its end
		t.Errorf("holder of a file no one locks = %q, want none", got)
	}
}

// A file's key is what /proc/locks writes for it, whatever the device numbers: a minor or a major past one byte
// (anonymous devices, many mounts) spreads over the high bits of dev_t.
func TestDevKeyIsWhatProcLocksWrites(t *testing.T) {
	makedev := func(major, minor uint64) uint64 {
		return minor&0xff | (major&0xfff)<<8 | (minor&^0xff)<<12 | (major&^0xfff)<<32
	}
	for _, c := range []struct {
		major, minor uint64
		want         string
	}{
		{8, 1, "08:01:7"}, {259, 2, "103:02:7"}, {0, 0x13a, "00:13a:7"}, {0x1234, 0x56789, "1234:56789:7"},
	} {
		if got := devKey(makedev(c.major, c.minor), 7); got != c.want {
			t.Errorf("devKey(%d:%d) = %q, want %q", c.major, c.minor, got, c.want)
		}
	}
}
