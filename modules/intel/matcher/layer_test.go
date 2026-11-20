package matcher

import (
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// A tech whose every category is an edge one — CDN 31, reverse proxy 64, load balancer 65 — is the edge layer; a tech
// that can also be the origin (a web server that proxies, a cache) or has no category is left unplaced, never "origin".
func TestDetectionLayer(t *testing.T) {
	d := db(map[string]schema.Fingerprint{
		"Cloudflare": {Cats: []int{31}, Headers: map[string]schema.StringList{"cf-ray": {""}}},
		"Envoy":      {Cats: []int{64}, Headers: map[string]schema.StringList{"x-envoy-upstream-service-time": {""}}},
		"Balancer":   {Cats: []int{65, 31}, Headers: map[string]schema.StringList{"x-lb": {""}}},
		"Squid":      {Cats: []int{64, 23}, Headers: map[string]schema.StringList{"x-squid-error": {""}}},
		"Nginx":      {Cats: []int{22}, Headers: map[string]schema.StringList{"server": {`nginx(?:/([\d.]+))?\;version:\1`}}},
		"Plain":      {Headers: map[string]schema.StringList{"x-plain": {""}}},
	})
	page := Page{Headers: map[string][]string{"cf-ray": {"1"}, "x-envoy-upstream-service-time": {"2"}, "x-lb": {"1"},
		"x-squid-error": {"1"}, "server": {"nginx/1.18.0"}, "x-plain": {"1"}}}
	want := map[string]string{"Cloudflare": "edge", "Envoy": "edge", "Balancer": "edge", "Squid": "", "Nginx": "", "Plain": ""}
	got := Match(d, page)
	if len(got) != len(want) {
		t.Fatalf("detections %+v, want %d", got, len(want))
	}
	for _, det := range got {
		if det.Layer != want[det.Tech] {
			t.Errorf("%s: layer %q, want %q", det.Tech, det.Layer, want[det.Tech])
		}
	}
}
