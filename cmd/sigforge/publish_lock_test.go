package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// snapshotFiles reads every file of a published DB (DB, sidecar, manifest and their .prev), "" for a missing one.
func snapshotFiles(t *testing.T, db string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range []string{db, db + ".sha256", db + ".manifest.json", db + ".prev", db + ".prev.sha256", db + ".prev.manifest.json"} {
		b, _ := os.ReadFile(p)
		out[filepath.Base(p)] = string(b)
	}
	return out
}

// While one publish holds <out>.lock, a second merge, refresh or rollback of the same DB fails naming the lock and the
// holder's PID and touches none of the files: two publishes interleaved used to leave a DB with another run's sidecar
// and manifest, which verify then refused (4 of 40 overlapping runs, measured). Once it is released, publishing works.
func TestPublishLockRefusesASecondWriter(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	db, man := filepath.Join(dir, "db.json"), filepath.Join(dir, "m.json")
	src := filepath.Join(dir, "a.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	captureStdout(t, func() {
		if err := cmdMerge([]string{"--out", db, "--manifest", man}); err != nil {
			t.Fatal(err)
		}
		if err := cmdMerge([]string{"--out", db, "--manifest", man, "--source", "a=" + src}); err != nil {
			t.Fatal(err)
		}
	})
	before := snapshotFiles(t, db)
	release := mustLock(t, db) // another publish is running
	held := db + ".lock " + heldByThisRun()
	for name, run := range map[string]func() error{
		"merge":    func() error { return cmdMerge([]string{"--out", db, "--manifest", man}) },
		"refresh":  func() error { return cmdRefresh([]string{"--out", db, "--manifest", man, "--source", "a=" + src}) },
		"rollback": func() error { return cmdRollback([]string{db}) },
	} {
		var err error
		captureStdout(t, func() { err = run() })
		if err == nil || !strings.Contains(err.Error(), held) {
			t.Errorf("%s with the lock held: err = %v, want a refusal naming the lock and its PID", name, err)
		}
		if after := snapshotFiles(t, db); !mapsEqual(before, after) {
			t.Errorf("%s with the lock held changed the published files", name)
		}
	}
	release()
	captureStdout(t, func() {
		if err := cmdMerge([]string{"--out", db, "--manifest", man}); err != nil {
			t.Fatalf("with the lock released a merge must publish: %v", err)
		}
	})
	mustLock(t, db)() // a finished publish holds nothing
}

// heldByThisRun is how a refusal names this test process as the holder: its PID, read from the system on Linux.
func heldByThisRun() string {
	if runtime.GOOS == "linux" {
		return fmt.Sprintf("held by PID %d (try again once it is done)", os.Getpid())
	}
	return "held by another run (try again once it is done)"
}

// mustLock takes the publish lock of db, failing the test when it cannot, and returns its release.
func mustLock(t *testing.T, db string) func() {
	t.Helper()
	release, err := lockPublish(db)
	if err != nil {
		t.Fatalf("the publish lock of %s must be free: %v", db, err)
	}
	return release
}

// A lock file a run left behind — killed, or written by an older sigforge — is not a lock: only a running publish
// holds one, so a run that died never blocks the next and nothing is removed by hand.
func TestALeftLockFileIsNotALock(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db.json")
	writeFile(t, db+".lock", "4242\n")
	release := mustLock(t, db)
	if _, err := lockPublish(db); err == nil || !strings.Contains(err.Error(), heldByThisRun()) {
		t.Errorf("a second lock while this run holds it: err = %v, want a refusal naming this run (%q), never the file's 4242", err, heldByThisRun())
	}
	release()
	if got, _ := os.ReadFile(db + ".lock"); string(got) != "4242\n" {
		t.Errorf("the lock file was written: %q — sigforge never writes it", got)
	}
}

// A lock taken by any process on the file — not sigforge, nothing written in it — is refused all the same, and the
// refusal names the holder the system reports.
func TestPublishLockNamesTheHolderTheSystemReports(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db.json")
	f, err := os.OpenFile(db+".lock", os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if held, err := tryLock(f); held || err != nil {
		t.Fatalf("taking a free lock: held %v, err %v", held, err)
	}
	if _, err := lockPublish(db); err == nil || !strings.Contains(err.Error(), heldByThisRun()) {
		t.Errorf("a lock another open of the file holds: err = %v, want the holder named %q", err, heldByThisRun())
	}
}

// A publish that fails after taking the lock — a refresh the gate refuses, a rollback of a corrupt archive — releases
// it, so the next run is not blocked by a lock nobody holds.
func TestPublishLockReleasedOnError(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	db, man := filepath.Join(dir, "db.json"), filepath.Join(dir, "m.json")
	ab, a := filepath.Join(dir, "ab.json"), filepath.Join(dir, "a.json")
	writeFile(t, ab, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]},"ProbeB":{"html":["marker-b"]}}}`)
	writeFile(t, a, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	captureStdout(t, func() {
		if err := cmdRefresh([]string{"--out", db, "--manifest", man, "--source", "ab=" + ab}); err != nil {
			t.Fatal(err)
		}
	})
	var err error
	captureStdout(t, func() { err = cmdRefresh([]string{"--out", db, "--manifest", man, "--source", "a=" + a}) })
	if err == nil || !strings.Contains(err.Error(), "REGRESSION") {
		t.Fatalf("dropping a tech must be refused by the gate, got %v", err)
	}
	mustLock(t, db)() // a refused refresh released it
	writeFile(t, db+".prev", "corrupt")
	writeFile(t, db+".prev.sha256", strings.Repeat("0", 64)+"  db.json.prev\n")
	captureStdout(t, func() { err = cmdRollback([]string{db}) })
	if err == nil {
		t.Fatal("a corrupt archive must not be rolled back")
	}
	mustLock(t, db)() // a refused rollback released it
	captureStdout(t, func() { err = cmdRefresh([]string{"--out", db, "--manifest", man, "--source", "ab=" + ab}) })
	if err != nil {
		t.Errorf("after refused runs the next publish must work: %v", err)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// The lock is taken before refresh reads the live DB, so the gate compares the candidate with the DB this run replaces:
// with the lock held, a refresh fails on the lock even when the live DB cannot be read.
func TestPublishLockTakenBeforeTheLiveDBIsRead(t *testing.T) {
	offline(t)
	dir := t.TempDir()
	db, src := filepath.Join(dir, "db.json"), filepath.Join(dir, "a.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	writeFile(t, db, "not a DB")
	defer mustLock(t, db)()
	var err error
	captureStdout(t, func() {
		err = cmdRefresh([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err == nil || !strings.Contains(err.Error(), heldByThisRun()) {
		t.Errorf("refresh with the lock held and an unreadable live DB: err = %v, want the lock refusal (the lock comes first)", err)
	}
}

// A lock file another user left and this one cannot write — a run under sudo once, the service user after — does not
// block: every run locks it through a read-only descriptor and never changes it.
func TestALockFileOthersCannotWriteDoesNotBlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("file modes do not bind root")
	}
	db := filepath.Join(t.TempDir(), "db.json")
	writeFile(t, db+".lock", "")
	if err := os.Chmod(db+".lock", 0o444); err != nil {
		t.Fatal(err)
	}
	release := mustLock(t, db)
	if _, err := lockPublish(db); err == nil || !strings.Contains(err.Error(), heldByThisRun()) {
		t.Errorf("a second run while a read-only holder has it: err = %v, want a refusal naming it", err)
	}
	release()
	if st, err := os.Stat(db + ".lock"); err != nil || st.Mode().Perm() != 0o444 {
		t.Errorf("the lock file of another user was changed: %v, %v — want it left 0444", st, err)
	}
}

// The lock file outlives the run that made it, unchanged, and only one run ever holds it: removing it on release would
// let a run that opened it before the release and a run that creates a new one both hold "the" lock.
func TestPublishLockFileOutlivesARun(t *testing.T) {
	db := filepath.Join(t.TempDir(), "db.json")
	releaseA := mustLock(t, db)
	b, err := os.OpenFile(db+".lock", os.O_RDWR, 0) // B opens the file while A holds it
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	releaseA()
	if got, err := os.ReadFile(db + ".lock"); err != nil || len(got) != 0 {
		t.Errorf("after release the lock file = %q, %v: want it kept, empty as made", got, err)
	}
	if held, err := tryLock(b); held || err != nil {
		t.Fatalf("B taking the released lock: held %v, err %v", held, err)
	}
	if _, err := lockPublish(db); err == nil {
		t.Errorf("C took the lock while B holds it: two holders")
	}
}

// A lock call that fails — not "held", an error — is never taken for a lock: the run stops naming the error and
// publishes nothing.
func TestPublishLockFailsWhenLockingFails(t *testing.T) {
	defer func(orig func(*os.File) (bool, error)) { lockFile = orig }(lockFile)
	lockFile = func(*os.File) (bool, error) { return false, errors.New("no locks left") }
	offline(t)
	dir := t.TempDir()
	db, src := filepath.Join(dir, "db.json"), filepath.Join(dir, "a.json")
	writeFile(t, src, `{"schema_version":"1.0.0","fingerprints":{"ProbeA":{"html":["marker-a"]}}}`)
	var err error
	captureStdout(t, func() {
		err = cmdMerge([]string{"--out", db, "--manifest", filepath.Join(dir, "m.json"), "--source", "a=" + src})
	})
	if err == nil || !strings.Contains(err.Error(), "no locks left") {
		t.Errorf("merge with a failing lock call: err = %v, want it named", err)
	}
	if _, serr := os.Stat(db); !os.IsNotExist(serr) {
		t.Errorf("merge published without the lock: %v", serr)
	}
}
