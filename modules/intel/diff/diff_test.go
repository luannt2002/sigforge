package diff

import (
	"reflect"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

func db(fps map[string]schema.Fingerprint) *schema.DB {
	return &schema.DB{SchemaVersion: schema.SchemaVersion, Fingerprints: fps}
}

func TestDiff(t *testing.T) {
	nginx := schema.Fingerprint{Headers: map[string]schema.StringList{"Server": {"nginx"}}, Provenance: "baseline"}
	nginxBumped := nginx
	nginxBumped.ProvenanceVersion = "v2" // same markers, version differs → changed
	nginxMarker := schema.Fingerprint{Headers: map[string]schema.StringList{"Server": {"nginx/(\\d+)"}}, Provenance: "baseline"}
	php := schema.Fingerprint{Headers: map[string]schema.StringList{"X-Powered-By": {"PHP"}}}

	tests := []struct {
		name     string
		old, new *schema.DB
		want     Result
	}{
		{
			name: "added",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php}),
			want: Result{Added: []string{"PHP"}},
		},
		{
			name: "removed",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginx}),
			want: Result{Removed: []string{"PHP"}},
		},
		{
			name: "changed-version",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginxBumped}),
			want: Result{Changed: []string{"Nginx"}},
		},
		{
			name: "changed-marker",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginxMarker}),
			want: Result{Changed: []string{"Nginx"}},
		},
		{
			name: "identical",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php}),
			want: Result{},
		},
		{
			name: "nil-old-is-all-added",
			old:  nil,
			new:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php}),
			want: Result{Added: []string{"Nginx", "PHP"}},
		},
		{
			name: "mixed-sorted",
			old:  db(map[string]schema.Fingerprint{"Nginx": nginx, "PHP": php, "Zend": php}),
			new:  db(map[string]schema.Fingerprint{"Nginx": nginxBumped, "Apache": php, "Caddy": php}),
			want: Result{Added: []string{"Apache", "Caddy"}, Removed: []string{"PHP", "Zend"}, Changed: []string{"Nginx"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Diff(tt.old, tt.new)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Diff() = %+v, want %+v", got, tt.want)
			}
			if tt.name == "identical" && !got.Empty() {
				t.Errorf("identical DBs should report Empty()")
			}
		})
	}
}

// Validate: diff A A is empty.
func TestDiffIdentityEmpty(t *testing.T) {
	a := db(map[string]schema.Fingerprint{
		"Nginx": {Headers: map[string]schema.StringList{"Server": {"nginx"}}, VersionRegex: []string{"nginx/([\\d.]+)"}},
		"PHP":   {Headers: map[string]schema.StringList{"X-Powered-By": {"PHP"}}},
	})
	if got := Diff(a, a); !got.Empty() {
		t.Errorf("Diff(A, A) = %+v, want empty", got)
	}
}
