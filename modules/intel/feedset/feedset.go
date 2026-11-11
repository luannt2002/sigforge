// Package feedset builds one run's intel sources from the operator's SIGFORGE_* environment, so
// every consumer — the sigforge CLI, a scanner importing sigforge — wires the same feeds the same
// way. Each source reads its URL from its own variable; unset = off, and its results are honestly
// not_checked. Build one Set per run: each catalog loads once per Set.
package feedset

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/cve"
	"github.com/luannt2002/sigforge/modules/intel/enrich"
	"github.com/luannt2002/sigforge/modules/intel/identity"
	"github.com/luannt2002/sigforge/modules/intel/jslib"
	"github.com/luannt2002/sigforge/modules/intel/kev"
	"github.com/luannt2002/sigforge/modules/intel/lifecycle"
	"github.com/luannt2002/sigforge/modules/intel/osv"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// EnvCacheDir names the operator's store for fetched sources.
const EnvCacheDir = "SIGFORGE_CACHE_DIR"

// EnvCacheMaxAge is how long a synced catalog in SIGFORGE_CACHE_DIR is used without asking
// its source (a Go duration, e.g. 24h). Unset = every run asks (304 when unchanged).
const EnvCacheMaxAge = "SIGFORGE_CACHE_MAX_AGE"

// Client builds the fetch client a run's sources share, with the store and max age from env.
// A max age that is not a duration is ignored — every catalog is asked fresh — and named in note.
func Client() (c *fetch.Client, note string) {
	c = fetch.New()
	c.CacheDir = strings.TrimSpace(os.Getenv(EnvCacheDir))
	if v := strings.TrimSpace(os.Getenv(EnvCacheMaxAge)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < 0 {
			note = fmt.Sprintf("note: ignoring %s=%q (want a duration like 24h): every catalog is asked fresh", EnvCacheMaxAge, v)
		} else {
			c.MaxAge = d
		}
	}
	return c, note
}

// NewEOL uses the operator's one-request bundle when set (every product in one fetch),
// else the per-product feed (one fetch per detected product).
func NewEOL(client *fetch.Client) *lifecycle.Adapter {
	if u := strings.TrimSpace(os.Getenv(lifecycle.EnvBundleURL)); u != "" {
		return lifecycle.NewBundle(u, client)
	}
	return lifecycle.New(os.Getenv(lifecycle.EnvVar), client)
}

// Set is one run's configured sources: Options goes to enrich, Notes reports the caveats.
type Set struct {
	Options enrich.Options

	resolver     *identity.Resolver
	kev          *kev.Adapter
	dictURL      string
	kevURL       string
	identityUsed atomic.Bool
	kevUsed      atomic.Bool
}

// New wires every source from env over one client.
func New(client *fetch.Client) *Set {
	s := &Set{dictURL: os.Getenv(identity.EnvCPEDictURL), kevURL: os.Getenv(kev.EnvKEVURL)}
	s.resolver = identity.New(s.dictURL, client)
	s.kev = kev.New(s.kevURL, os.Getenv(kev.EnvEPSSURL), client)
	wp := wpcve.New(os.Getenv(wpcve.EnvWPVulnURL), os.Getenv(wpcve.EnvWPOrgURL), client)
	js := jslib.New(os.Getenv(jslib.EnvRetireJSURL), client)
	s.Options = enrich.Options{
		CVE: cve.New(os.Getenv(cve.EnvVar), client),
		EOL: NewEOL(client),
		KEV: kevUse{s.kev, &s.kevUsed},
		WP: func(ctx context.Context, slug, version, kind string) unified.Result {
			switch kind {
			case "", "plugin": // enrich.WPLookup documents plugin as the default kind
				return wpcve.ToUnified(wp.LookupPlugin(ctx, slug, version))
			case "theme":
				return wpcve.ToUnified(wp.LookupTheme(ctx, slug, version))
			case "core":
				return wpcve.CoreToUnified(wp.LookupCore(ctx, version))
			}
			// a plugin answer for any other kind would be about a different product
			r := unified.Unknown("wordpress:"+kind, slug, unified.StateNotChecked, fmt.Sprintf("WordPress kind %q is not plugin, theme or core: not looked up", kind))
			r.Source, r.Version = "wpcve", version
			return r
		},
		JS: func(ctx context.Context, name, version string) unified.Result {
			return jslib.ToUnified(js.LookupOne(ctx, name, version))
		},
		IdentityResolver: func(ctx context.Context, name, vendor, product string) (string, string, identity.State) {
			s.identityUsed.Store(true)
			return s.resolver.ResolveCPE(ctx, name, vendor, product)
		},
	}
	// unset: enrich names the gap for a package it is asked about; a detected platform is not looked up
	if u := strings.TrimSpace(os.Getenv(osv.EnvOSVURL)); u != "" {
		s.Options.OSV, s.Options.OSVRelease = osv.New(u, client).Lookupers()
	}
	return s
}

// Notes are the run's caveats to show beside its results: a configured catalog that is not in
// use or is stale, a partial CPE dictionary. A source is asked only when this run used it —
// asking an unused one would fetch its whole catalog just to print a note.
func (s *Set) Notes(ctx context.Context) []string {
	var out []string
	if s.dictURL != "" && s.identityUsed.Load() {
		if n := dictNote(s.resolver.Status(ctx)); n != "" {
			out = append(out, n)
		}
	}
	if s.kevURL != "" && s.kevUsed.Load() {
		if n := kevNote(s.kev.Status(ctx)); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// kevUse records that the run asked the KEV adapter, so its status is read only once the
// catalog was loaded anyway.
type kevUse struct {
	*kev.Adapter
	used *atomic.Bool
}

func (k kevUse) EnrichUnified(ctx context.Context, ids []string) map[string]unified.Result {
	k.used.Store(true)
	return k.Adapter.EnrichUnified(ctx, ids)
}

// kevNote explains that the configured live KEV catalog is not what prioritized the
// leads, or what in it needs a look though it is in use; "" when there is nothing to say.
func kevNote(s kev.CatalogStatus) string {
	switch {
	case s.Err == "" && s.Warn != "":
		return "note: KEV catalog in use, but " + s.Warn
	case s.Err == "":
		return ""
	case s.Source == "live": // the source failed, but the last synced copy is in use
		return fmt.Sprintf("note: KEV catalog source failed (%s) — leads prioritized against the last synced copy (stale, %d entries)", s.Err, s.Entries)
	}
	return fmt.Sprintf("note: KEV catalog from %s is not in use (%s) — leads prioritized against the embedded snapshot only (%d entries)",
		kev.EnvKEVURL, s.Err, s.Entries)
}

// dictNote explains why CPE identity is narrower than the operator configured — a live
// dictionary that is not in use, or only one page of a paged feed — and is "" when the
// configured dictionary is fully in use.
func dictNote(s identity.DictStatus) string {
	switch {
	case s.Source != "live":
		return fmt.Sprintf("note: CPE dictionary from %s is not in use (%s) — identity matched against the embedded sample only (%d CPE bases)",
			identity.EnvCPEDictURL, s.Err, s.Entries)
	case s.Err != "": // the source failed, but the last synced copy is in use
		return fmt.Sprintf("note: CPE dictionary source failed (%s) — identity matched against the last synced copy (stale, %d CPE bases)", s.Err, s.Entries)
	case s.Partial():
		return fmt.Sprintf("note: CPE dictionary is one page of a paged feed (%d of %d products) — no identity is verified against it (one page cannot show a match is unique)",
			s.Products, s.Total)
	}
	return ""
}
