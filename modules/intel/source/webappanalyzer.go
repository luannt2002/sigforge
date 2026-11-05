package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// webappanalyzer adapts the enthec/webappanalyzer dataset (the maintained
// continuation of Wappalyzer's fingerprint data). Its JSON uses the same
// Wappalyzer shape as sigforge's schema, so Normalize is a near-direct decode. The
// dataset is GPL-3.0, so every produced entry is tagged accordingly and is never
// vendored here — it is fetched by the operator under that license.
type webappanalyzer struct {
	url    string
	client *fetch.Client
}

func (w *webappanalyzer) Name() string    { return "webappanalyzer" }
func (w *webappanalyzer) License() string { return "GPL-3.0" }

func (w *webappanalyzer) Fetch(ctx context.Context) ([]byte, error) {
	if err := requireURL(w.Name(), w.url); err != nil {
		return nil, err
	}
	return w.client.Get(ctx, w.url)
}

// Normalize decodes a Wappalyzer technologies document. It accepts both the wrapped
// form ({"technologies": {...}, "categories": {...}}) and a bare technology map
// ({"Nginx": {...}, ...}, as enthec's split src/technologies/*.json files use). A
// single malformed entry is dropped so one bad record does not fail the whole set.
func (w *webappanalyzer) Normalize(raw []byte) (map[string]schema.Fingerprint, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, fmt.Errorf("webappanalyzer: decode: %w", err)
	}
	techs := top
	if t, ok := top["technologies"]; ok {
		var inner map[string]json.RawMessage
		if json.Unmarshal(t, &inner) == nil && len(inner) > 0 {
			techs = inner
		}
	}
	out := make(map[string]schema.Fingerprint, len(techs))
	for name, r := range techs {
		if name == "" {
			continue
		}
		// cats/implies/dom decode directly into Fingerprint. cpe is the exception:
		// the source writes it as a single string, so a bare `CPE []string` field
		// would fail the whole-entry decode and silently drop every CVE-ready
		// entry. The outer StringList (string-or-array) shadows the embedded field's
		// "cpe" tag, absorbing it safely; we then copy it onto the real field.
		var e struct {
			schema.Fingerprint
			CPE schema.StringList `json:"cpe"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			continue
		}
		fp := e.Fingerprint
		fp.CPE = e.CPE
		fp.Provenance = w.Name()
		fp.License = w.License()
		out[name] = fp
	}
	if len(out) == 0 {
		return nil, errors.New("webappanalyzer: no technologies in input")
	}
	return out, nil
}
