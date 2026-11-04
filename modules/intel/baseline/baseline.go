// Package baseline is sigforge's curated, permissively-licensed fingerprint set,
// embedded in the binary so a consumer always has a working DB offline with zero
// configuration. Every entry is authored from public facts (a Server header, a
// cookie name, a path) and carries provenance "baseline" and an Apache-2.0
// license; no third-party fingerprint data is vendored here.
package baseline

import (
	_ "embed"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

//go:embed data/baseline.json
var baselineJSON []byte

// Bytes returns the raw embedded baseline JSON (e.g. for the CLI's `baseline`
// command to emit verbatim).
func Bytes() []byte { return baselineJSON }

// DB returns the parsed, validated baseline fingerprint set.
func DB() (*schema.DB, error) {
	return schema.Parse(baselineJSON)
}
