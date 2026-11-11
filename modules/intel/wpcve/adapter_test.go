package wpcve

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// vulnFeed serves one canned body for every slug.
func vulnFeed(t *testing.T, body string) *Provider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return New(srv.URL+"/{slug}", "", fetch.New())
}

// Each wpcve tri-state branch must land on its own unified.State, and UNKNOWN must
// never be promoted to a clean (not_affected) verdict.
func TestToUnifiedStates(t *testing.T) {
	ctx := context.Background()

	// affected: feed knows the slug, one vuln hits the installed version.
	affected := vulnFeed(t, `{"acme":{"vulnerabilities":[{"id":"V1","title":"XSS","cve":"CVE-2024-0001","min_version":"1.0","max_version":"5.0","cvss_score":"9.8"}]}}`).
		LookupPlugin(ctx, "acme", "1.2.0")
	if got := ToUnified(affected); got.State != unified.StateAffectedByAdvisory || len(got.Leads) != 1 || got.Freshness != unified.FreshnessLive {
		t.Fatalf("affected ⇒ affected_by_advisory + 1 lead + live, got state=%s leads=%d fresh=%s", got.State, len(got.Leads), got.Freshness)
	}

	// not-affected: feed knows the slug, installed version outside every range.
	notAff := vulnFeed(t, `{"acme":{"vulnerabilities":[{"id":"V1","title":"old","min_version":"0.1","max_version":"0.5"}]}}`).
		LookupPlugin(ctx, "acme", "1.2.0")
	if got := ToUnified(notAff); got.State != unified.StateNotChecked || got.Err == "" || len(got.Leads) != 0 {
		t.Fatalf("version out of range ⇒ not_checked with a reason and no lead, got state=%s leads=%d", got.State, len(got.Leads))
	}

	// unknown-version: feed knows the slug but the version is not comparable.
	unkVer := vulnFeed(t, `{"acme":{"vulnerabilities":[{"id":"V1","min_version":"1.0","max_version":"5.0"}]}}`).
		LookupPlugin(ctx, "acme", "trunk")
	if got := ToUnified(unkVer); got.State != unified.StateUnknownVersion {
		t.Fatalf("unparseable version ⇒ unknown_version, got %s", got.State)
	}

	// unknown-product: the feed answers but does not list this slug.
	unkProd := vulnFeed(t, `{"other":{"vulnerabilities":[]}}`).LookupPlugin(ctx, "ghost", "1.0.0")
	if got := ToUnified(unkProd); got.State != unified.StateUnknownProduct {
		t.Fatalf("slug the feed does not list ⇒ unknown_product, got %s", got.State)
	}

	// not-checked: the vuln feed is not configured.
	notChk := New("", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0.0")
	if got := ToUnified(notChk); got.State != unified.StateNotChecked {
		t.Fatalf("feed off ⇒ not_checked, got %s", got.State)
	}

	// source-unavailable: the feed is configured but dead (500).
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer down.Close()
	srcDown := New(down.URL+"/{slug}", "", fetch.New()).LookupPlugin(ctx, "acme", "1.0.0")
	if got := ToUnified(srcDown); got.State != unified.StateSourceUnavailable {
		t.Fatalf("dead feed ⇒ source_unavailable, got %s", got.State)
	}

	// honest-verdict: none of the UNKNOWN branches may read as clean/applicable.
	for name, pr := range map[string]PluginResult{"unknown_version": unkVer, "unknown_product": unkProd, "not_checked": notChk, "source_unavailable": srcDown} {
		if u := ToUnified(pr); u.State == unified.StateNotAffectedByAdvisory || u.State.Applicable() {
			t.Errorf("%s must not be clean/applicable, got %s", name, u.State)
		}
	}

	// the two UNREACHED branches carry no fetched data ⇒ freshness stays unknown (never live).
	for name, pr := range map[string]PluginResult{"not_checked": notChk, "source_unavailable": srcDown} {
		if u := ToUnified(pr); u.Freshness != unified.FreshnessUnknown {
			t.Errorf("%s was never fetched ⇒ freshness must be unknown, got %s", name, u.Freshness)
		}
	}
}

// Scope follows the kind; identity is the slug.
func TestToUnifiedThemeScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `{"twentytwenty":{"vulnerabilities":[]}}`)
	}))
	defer srv.Close()
	res := New(srv.URL+"/{slug}", "", fetch.New()).LookupTheme(context.Background(), "twentytwenty", "1.5")
	u := ToUnified(res)
	if u.Scope != "wordpress:theme" || u.Identity != "twentytwenty" || u.Source != "wpcve" {
		t.Fatalf("theme scope/identity/source wrong: scope=%q id=%q src=%q", u.Scope, u.Identity, u.Source)
	}
	if u := ToUnified(New("", "", fetch.New()).LookupPlugin(context.Background(), "akismet", "1.0")); u.Scope != "wordpress:plugin" {
		t.Fatalf("plugin scope wrong: %q", u.Scope)
	}
}

// Lead mapping: CVE string → slice; Score is nil when no numeric CVSS (never 0.0),
// a pointer to the real value when present.
func TestToUnifiedLeadScore(t *testing.T) {
	ctx := context.Background()
	body := `{"acme":{"vulnerabilities":[
		{"id":"V1","cve":"CVE-2024-0001","min_version":"1.0","max_version":"5.0","cvss_score":"9.8"},
		{"id":"V2","min_version":"1.0","max_version":"5.0"}]}}`
	u := ToUnified(vulnFeed(t, body).LookupPlugin(ctx, "acme", "1.2.0"))
	if len(u.Leads) != 2 {
		t.Fatalf("want 2 leads, got %d", len(u.Leads))
	}
	scored, unscored := u.Leads[0], u.Leads[1]
	if scored.Score == nil || *scored.Score != 9.8 || scored.Severity != "critical" {
		t.Errorf("scored lead: want score 9.8/critical, got %+v", scored)
	}
	if len(scored.CVE) != 1 || scored.CVE[0] != "CVE-2024-0001" {
		t.Errorf("CVE must map string→slice, got %v", scored.CVE)
	}
	if unscored.Score != nil || unscored.Severity != "" {
		t.Errorf("no numeric CVSS ⇒ nil score + empty severity (never 0.0), got score=%v sev=%q", unscored.Score, unscored.Severity)
	}
	if len(unscored.CVE) != 0 {
		t.Errorf("no CVE ⇒ empty slice, got %v", unscored.CVE)
	}
}

// Core maps like a plugin under scope wordpress:core: each LookupCore branch lands on its own state, the
// reasons it keeps (off, down, core not listed) stay apart, and nothing is ever a clearance.
func TestCoreToUnifiedStates(t *testing.T) {
	ctx := context.Background()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer down.Close()
	listed := `{"wordpress":{"vulnerabilities":[{"id":"C1","min_version":"6.0","max_version":"6.4.3"}]}}`
	for _, c := range []struct {
		name  string
		res   CoreResult
		state unified.State
		fresh unified.Freshness
		leads int
	}{
		{"in range", vulnFeed(t, listed).LookupCore(ctx, "6.1"), unified.StateAffectedByAdvisory, unified.FreshnessLive, 1},
		{"no version", vulnFeed(t, listed).LookupCore(ctx, ""), unified.StatePotentiallyAffected, unified.FreshnessLive, 1},
		{"past every range", vulnFeed(t, listed).LookupCore(ctx, "6.8"), unified.StateNotChecked, unified.FreshnessLive, 0},
		{"unparseable version", vulnFeed(t, listed).LookupCore(ctx, "trunk"), unified.StateUnknownVersion, unified.FreshnessLive, 0},
		{"unreadable bound", vulnFeed(t, `{"wordpress":{"vulnerabilities":[{"id":"C9","max_version":"trunk"}]}}`).LookupCore(ctx, "6.1"), unified.StatePotentiallyAffected, unified.FreshnessLive, 1},
		{"core not listed", vulnFeed(t, `{"other":{"vulnerabilities":[]}}`).LookupCore(ctx, "6.1"), unified.StateUnknownProduct, unified.FreshnessLive, 0},
		{"core entry null", vulnFeed(t, `{"wordpress":null}`).LookupCore(ctx, "6.1"), unified.StateUnknownProduct, unified.FreshnessLive, 0},
		{"feed off", New("", "", fetch.New()).LookupCore(ctx, "6.1"), unified.StateNotChecked, unified.FreshnessUnknown, 0},
		{"feed down", New(down.URL+"/{kind}/{slug}", "", fetch.New()).LookupCore(ctx, "6.1"), unified.StateSourceUnavailable, unified.FreshnessUnknown, 0},
	} {
		u := CoreToUnified(c.res)
		if u.State != c.state || u.Freshness != c.fresh || len(u.Leads) != c.leads || u.Scope != "wordpress:core" || u.Identity != "wordpress" || u.Source != "wpcve" {
			t.Errorf("%s: got state=%s fresh=%s leads=%d scope=%q id=%q src=%q; want %s, %s, %d leads on wordpress:core",
				c.name, u.State, u.Freshness, len(u.Leads), u.Scope, u.Identity, u.Source, c.state, c.fresh, c.leads)
		}
		if u.State == unified.StateNotChecked && u.Err == "" {
			t.Errorf("%s: not_checked must say why", c.name)
		}
	}
}
