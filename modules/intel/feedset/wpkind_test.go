package feedset

import (
	"context"
	"testing"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/unified"
	"github.com/luannt2002/sigforge/modules/intel/wpcve"
)

// With the WordPress feed on, a kind the feed has no lookup for (not plugin, theme or core) is not looked up — and says
// why in a code, as the same case with the feed off does in enrich: a consumer never sees an unconcluded result with no reason.
func TestWPKindNotCoveredNamesItsReason(t *testing.T) {
	t.Setenv(wpcve.EnvWPVulnURL, "http://127.0.0.1:9/{slug}")
	s := New(fetch.New())
	r := s.Options.WP(context.Background(), "acme", "1.0", "mu-plugin")
	if r.State != unified.StateNotChecked || r.Reason != unified.ReasonUnsupported || r.Scope != "wordpress:mu-plugin" {
		t.Errorf("kind mu-plugin with the feed on = %s / %q / %s, want not_checked / unsupported / wordpress:mu-plugin", r.State, r.Reason, r.Scope)
	}
}
