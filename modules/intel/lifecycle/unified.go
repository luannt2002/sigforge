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
//	no product name / CPE to ask  → StateNotChecked + no_identity (the source was not asked)
//	CPE the bundle lists twice     → StateNotChecked + no_identity (the bundle was read; none guessed)
//	StateUnknown, bundle lacks it  → StateUnknownProduct + not_in_source (the bundle was read)
//	StateUnknown, product mapped   → StateUnknownVersion (cycle unmatched / eol unreadable)
//
// Freshness is Live whenever the feed was actually read (Snapshot when it came from the
// locally synced bundle, Stale when the source failed and the stored copy answered) — a miss
// included; the off, error and not-asked paths read nothing, so it stays Unknown.
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
		u.State, u.Reason = unified.StateNotChecked, unified.ReasonSourceOff
	case err != nil:
		u.State, u.Reason = unified.StateSourceUnavailable, unified.ReasonSourceError
		u.Err = err.Error()
	case st.IsEOL == StateEOL:
		u.State = unified.AdvisoryState(st.Version != "")
		if st.Version == "" {
			u.Err, u.Reason = unified.JoinNotes(u.Err, unified.NoteNoVersion), unified.ReasonNoVersion // keep a stale note
		}
		u.Freshness = fresh
		title := "cycle " + st.Cycle + " reached end-of-life"
		if _, err := time.Parse("2006-01-02", st.EOLDate); err == nil {
			title += " on " + st.EOLDate
		} else {
			title += " (the source gives no date)" // the feed's flag (isEol / eol true), never put where a date goes
		}
		u.Leads = []unified.Lead{{ID: "eol:" + st.Product + ":" + st.Cycle, Title: title}}
	case st.IsEOL == StateSupported:
		var why string
		u.State, why = unified.Clean(unified.Evidence{FullData: true, Positioned: true})
		if u.Err != "" {
			why = unified.JoinNotes(u.Err, why) // keep the stale note
		}
		u.Err = why
		u.Reason = unified.ReasonNoClearance
		u.Freshness = fresh
	case st.shared: // set only when the bundle named no one product
		u.State, u.Reason = unified.StateNotChecked, unified.ReasonNoIdentity
		u.Err = unified.JoinNotes(u.Err, "the end-of-life source lists this CPE under more than one product: none is guessed")
		u.Freshness = fresh // the bundle was read
	case st.Product == "" && st.unasked:
		u.State, u.Reason = unified.StateNotChecked, unified.ReasonNoIdentity
		u.Err = "no product name of the end-of-life source is known for this tech: not looked up"
	case st.Product == "":
		u.State, u.Reason = unified.StateUnknownProduct, unified.ReasonNotInSource
		if st.answered {
			u.Freshness = fresh // the bundle was read: its "not listed" is as fresh as its data
		}
	default:
		// product is mapped and the feed was fetched, but no cycle matched the
		// version (or its eol value was unreadable): the version, not the product.
		u.State, u.Reason = unified.StateUnknownVersion, unified.ReasonVersionUnplaced
		switch v := cycleName(st.Version); {
		case v == "":
			u.Reason = unified.ReasonNoVersion
		case v[0] < '0' || v[0] > '9':
			u.Reason = unified.ReasonVersionUnreadable
		}
		u.Freshness = fresh
	}
	return u
}

// EOLStatusUnified is EOLStatus plus ToUnified — the one call a unified consumer makes.
func (a *Adapter) EOLStatusUnified(ctx context.Context, tech, version string) unified.Result {
	st, err := a.EOLStatus(ctx, tech, version)
	return ToUnified(st, err)
}
