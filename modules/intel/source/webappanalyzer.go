package source

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"

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
// single malformed entry is dropped so one bad record does not fail the whole set. An
// entry whose requires/requiresCategory/excludes cannot be read is QUARANTINED (not
// emitted, counted and logged with its reason): emitted without its condition it would
// fire where the source's rule never would.
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
	var quarantined []string
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
			// Shadowed like cpe: an unreadable condition is quarantined, not lost in a failed decode.
			Requires         json.RawMessage `json:"requires"`
			RequiresCategory json.RawMessage `json:"requiresCategory"`
			Excludes         json.RawMessage `json:"excludes"`
		}
		if err := json.Unmarshal(r, &e); err != nil {
			continue
		}
		fp := e.Fingerprint
		fp.CPE = e.CPE
		if reason := decodeConditions(&fp, e.Requires, e.RequiresCategory, e.Excludes); reason != "" {
			quarantined = append(quarantined, name+": "+reason)
			continue
		}
		fp.Provenance = w.Name()
		fp.License = w.License()
		out[name] = fp
	}
	if len(quarantined) > 0 {
		sort.Strings(quarantined)
		log.Printf("webappanalyzer: quarantined %d technolog(ies) whose requires/requiresCategory/excludes cannot be evaluated (not emitted, the condition would be lost): %v", len(quarantined), quarantined)
	}
	if len(out) == 0 {
		return nil, errors.New("webappanalyzer: no technologies in input")
	}
	return out, nil
}

// decodeConditions sets fp's conditions or names the first unreadable one; null is absent, as in Wappalyzer.
func decodeConditions(fp *schema.Fingerprint, requires, requiresCategory, excludes json.RawMessage) string {
	var ok bool
	if fp.Requires, ok = techNames(requires); !ok {
		return "requires is not a list of technology names"
	}
	if fp.Excludes, ok = techNames(excludes); !ok {
		return "excludes is not a list of technology names"
	}
	if len(requiresCategory) > 0 && json.Unmarshal(requiresCategory, &fp.RequiresCategory) != nil {
		return "requiresCategory is not a list of category ids"
	}
	return ""
}

// techNames decodes a name or a list of names; a blank name refers to no technology.
func techNames(raw json.RawMessage) (schema.StringList, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, true
	}
	var names schema.StringList
	if json.Unmarshal(raw, &names) != nil {
		return nil, false
	}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			return nil, false
		}
	}
	return names, true
}
