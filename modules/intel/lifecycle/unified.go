package lifecycle

import (
	"context"
	"errors"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// ToUnified maps one EOLStatus outcome (its Status and error) into a
// unified.Result. An EOL version is treated as a LEAD (end of support is a real
// risk), a supported version as not_checked with unified.NoteNoClearance (no clearance
// is issued), and every kind of "we don't know" stays honestly unknown — never
// "supported" on absence:
//
//	feed off (ErrFeedOff)          → StateNotChecked
//	fetch/decode error             → StateSourceUnavailable
//	StateEOL                       → StateAffectedByAdvisory + one Lead (cycle + eol date)
//	StateSupported                 → StateNotChecked + unified.NoteNoClearance (no clearance)
//	StateUnknown, product unmapped → StateUnknownProduct
//	StateUnknown, product mapped   → StateUnknownVersion (cycle unmatched / eol unreadable)
//
// Freshness is Live whenever a mapped product's feed was actually fetched (Snapshot when
// it came from the locally synced bundle); an unmapped product and the off/error paths
// never fetch, so it stays Unknown.
// FetchedAt carries the feed's answer time (RFC3339) only when a fetch happened;
// a zero st.FetchedAt leaves it empty, never faked.
// lifecycle carries no CVE, so the Lead describes the cycle and eol date instead.
func ToUnified(st Status, err error) unified.Result {
	u := unified.Result{Scope: "eol", Identity: st.Product, Version: st.Version, Source: "lifecycle"}
	fresh := unified.FreshnessLive
	switch {
	case st.Stale:
		fresh = unified.FreshnessStale
		u.Err = "endoflife source failed: verdict from the last synced bundle (stale)"
		if st.Err != "" {
			u.Err += ": " + st.Err
		}
	case st.Cached:
		fresh = unified.FreshnessSnapshot // the locally synced bundle, as of its sync
	}
	if !st.FetchedAt.IsZero() {
		u.FetchedAt = st.FetchedAt.UTC().Format(time.RFC3339)
	}
	switch {
	case errors.Is(err, ErrFeedOff):
		u.State = unified.StateNotChecked
	case err != nil:
		u.State = unified.StateSourceUnavailable
		u.Err = err.Error()
	case st.IsEOL == StateEOL:
		u.State = unified.AdvisoryState(st.Version != "")
		u.Freshness = fresh
		u.Leads = []unified.Lead{{
			ID:    "eol:" + st.Product + ":" + st.Cycle,
			Title: "cycle " + st.Cycle + " reached end-of-life on " + st.EOLDate,
		}}
	case st.IsEOL == StateSupported:
		var why string
		u.State, why = unified.Clean(unified.Evidence{FullData: true, Positioned: true})
		if u.Err != "" {
			why = u.Err + "; " + why // keep the stale note
		}
		u.Err = why
		u.Freshness = fresh
	case st.Product == "":
		u.State = unified.StateUnknownProduct
	default:
		// product is mapped and the feed was fetched, but no cycle matched the
		// version (or its eol value was unreadable): the version, not the product.
		u.State = unified.StateUnknownVersion
		u.Freshness = fresh
	}
	return u
}

// EOLStatusUnified is EOLStatus plus ToUnified — the one call a unified consumer makes.
func (a *Adapter) EOLStatusUnified(ctx context.Context, tech, version string) unified.Result {
	st, err := a.EOLStatus(ctx, tech, version)
	return ToUnified(st, err)
}
