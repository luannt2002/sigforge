package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/luannt2002/sigforge/framework/fsio"
	"github.com/luannt2002/sigforge/modules/intel/osv"
)

// statusFile is where sync leaves each source's last outcome, in the store beside the copies.
const statusFile = "sync-status.json"

var now = time.Now

type sourceStatus struct {
	LastAttempt string `json:"last_attempt"`
	LastOK      string `json:"last_ok,omitempty"`
	Err         string `json:"error,omitempty"`
}

func readStatus(dir string) map[string]sourceStatus {
	m := map[string]sourceStatus{}
	if b, err := os.ReadFile(filepath.Join(dir, statusFile)); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

// recordSyncStatus folds one sync's outcomes into the store's status file. Best effort: a failed write
// loses the report, never the sync.
func recordSyncStatus(dir string, outcomes map[string]error) {
	m := readStatus(dir)
	at := now().UTC().Format(time.RFC3339)
	for name, err := range outcomes {
		s := m[name]
		s.LastAttempt, s.Err = at, ""
		if err != nil {
			s.Err = err.Error()
		} else {
			s.LastOK = at
		}
		m[name] = s
	}
	if b, err := json.MarshalIndent(m, "", "  "); err == nil {
		_ = fsio.WriteAtomic(filepath.Join(dir, statusFile), b, 0o644)
	}
}

// cmdSources reports, per source, what the last sync left — so a monitor can alarm on a source that
// is failing, was never synced or is older than --max-age, instead of scans quietly running on old
// or sample data.
func cmdSources(args []string) error {
	fs := flag.NewFlagSet("sources", flag.ContinueOnError)
	maxAge := fs.Duration("max-age", 0, "fail when a source in use last synced longer ago than this (0 = no age check)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := strings.TrimSpace(os.Getenv(EnvCacheDir))
	if dir == "" {
		return fmt.Errorf("sources: set %s to the local store directory", EnvCacheDir)
	}
	st := readStatus(dir)
	rows := append([]syncSource(nil), syncSources...)
	var dumps []string
	for name := range st {
		if strings.HasPrefix(name, "OSV ") {
			dumps = append(dumps, name)
		}
	}
	sort.Strings(dumps)
	for _, name := range dumps {
		rows = append(rows, syncSource{name: name, env: osv.EnvOSVURL})
	}
	bad := 0
	var unset []string
	for _, r := range rows {
		s, synced := st[r.name]
		line := "ok — synced " + s.LastOK
		switch {
		case strings.TrimSpace(os.Getenv(r.env)) == "":
			line = "off (" + r.env + " not set)"
			unset = append(unset, r.env)
		case !synced:
			line, bad = "never synced", bad+1
		case s.Err != "":
			line, bad = "FAILED at "+s.LastAttempt+": "+s.Err, bad+1
			if s.LastOK != "" {
				line += " (last ok " + s.LastOK + ")"
			}
		case *maxAge > 0:
			if at, err := time.Parse(time.RFC3339, s.LastOK); err != nil || now().Sub(at) > *maxAge {
				line, bad = "stale — last synced "+s.LastOK+", older than "+maxAge.String(), bad+1
			}
		}
		fmt.Printf("  %-22s %s\n", r.name, line)
	}
	// every source off checked nothing: passing would read as all well, as when a timer runs without the source variables
	if len(unset) == len(rows) {
		return fmt.Errorf("sources: no source in use, nothing was checked: %s not set", strings.Join(slices.Compact(unset), ", "))
	}
	if bad > 0 {
		return fmt.Errorf("sources: %d source(s) in use are failing, never synced or too old", bad)
	}
	return nil
}
