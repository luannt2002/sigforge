package enrich

import (
	"context"
	"reflect"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// With the WordPress feed off a slug keeps its kind's scope — core is never reported as a plugin — and a kind
// wpcve has no lookup for gets the result the wired feed (feedset) gives it: its own scope, never a plugin's.
// With the feed on, every kind still goes to the lookup untouched.
func TestWPOffScopesByKind(t *testing.T) {
	for _, c := range []struct{ kind, scope, err string }{
		{"", "wordpress:plugin", "wp feed off"},
		{"plugin", "wordpress:plugin", "wp feed off"},
		{"theme", "wordpress:theme", "wp feed off"},
		{"core", "wordpress:core", "wp feed off"},
		{"mu-plugin", "wordpress:mu-plugin", `WordPress kind "mu-plugin" is not plugin, theme or core: not looked up`},
	} {
		inp := EnrichInput{WPSlugs: []WPRef{{Slug: "s", Version: "1.0", Kind: c.kind}}}
		want := []unified.Result{{State: unified.StateNotChecked, Scope: c.scope, Identity: "s", Version: "1.0", Source: "wpcve", Err: c.err}}
		if got := EnrichUnifiedExt(context.Background(), nil, nil, inp, Options{}); !reflect.DeepEqual(got, want) {
			t.Errorf("kind %q with the WP feed off = %+v, want %+v", c.kind, got, want)
		}
		on := Options{WP: func(_ context.Context, slug, version, kind string) unified.Result {
			return unified.Result{Scope: "on:" + kind, Identity: slug, Version: version}
		}}
		if got := EnrichUnifiedExt(context.Background(), nil, nil, inp, on); !reflect.DeepEqual(got, []unified.Result{{Scope: "on:" + c.kind, Identity: "s", Version: "1.0"}}) {
			t.Errorf("kind %q with the WP feed on = %+v, want the lookup's own result", c.kind, got)
		}
	}
}
