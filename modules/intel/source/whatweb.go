package source

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// whatweb adapts WhatWeb plugins (Ruby files). This adapter does a BEST-EFFORT
// regex extraction of the string/pattern markers from the Ruby source — it does not
// run a Ruby parser.
//
// LICENSE: WhatWeb states GPL-2.0-or-later; the operator should confirm against the
// LICENSE of the exact revision they fetch (this adapter cannot read it offline).
//
// MAPPING LIMITS (honest): `:text` → HTML substring; `:regexp` → HTML regex;
// `:version` → HTML regex that also captures a version (its first group → version).
// NOT represented: `:md5`, `:ghdb` (Google-dork), `:account`, `:filepath`, `:url`
// and `:tagpattern` matchers, and the `:search => "headers[...]"` routing — every
// marker is flattened to a body scan, so a header-only plugin may under- or
// over-match. A Ruby regex that RE2 rejects is simply dropped at match time.
//
// FIELDS CARRIED beyond markers: none. WhatWeb plugins carry neither Wappalyzer
// numeric category ids nor a CPE, so there are no cats and no CPE to carry here.
type whatweb struct {
	url    string
	client *fetch.Client
}

func (p *whatweb) Name() string    { return "whatweb" }
func (p *whatweb) License() string { return "GPL-2.0-or-later" }

func (p *whatweb) Fetch(ctx context.Context) ([]byte, error) {
	if err := requireURL(p.Name(), p.url); err != nil {
		return nil, err
	}
	return p.client.Get(ctx, p.url)
}

var (
	wwName    = regexp.MustCompile(`(?m)(?:Plugin\.define|^\s*name)\s+["']([^"']+)["']`)
	wwText    = regexp.MustCompile(`:text\s*=>\s*(?:"([^"]*)"|'([^']*)')`)
	wwRegexp  = regexp.MustCompile(`:regexp\s*=>\s*/((?:\\.|[^/\\])*)/[imxoesun]*`)
	wwVersion = regexp.MustCompile(`:version\s*=>\s*/((?:\\.|[^/\\])*)/[imxoesun]*`)
)

func (p *whatweb) Normalize(raw []byte) (map[string]schema.Fingerprint, error) {
	src := string(raw)
	m := wwName.FindStringSubmatch(src)
	if m == nil {
		return nil, errors.New("whatweb: no plugin name found")
	}
	name := m[1]

	fp := schema.Fingerprint{}
	for _, t := range wwText.FindAllStringSubmatch(src, -1) {
		if v := t[1] + t[2]; v != "" { // one branch matched, the other is empty
			fp.HTML = append(fp.HTML, regexp.QuoteMeta(v))
		}
	}
	for _, r := range wwRegexp.FindAllStringSubmatch(src, -1) {
		if v := strings.TrimSpace(r[1]); v != "" {
			fp.HTML = append(fp.HTML, v)
		}
	}
	for _, r := range wwVersion.FindAllStringSubmatch(src, -1) {
		v := strings.TrimSpace(r[1])
		if v == "" {
			continue
		}
		if strings.Contains(v, "(") { // a capture group → map its first group to the version
			fp.HTML = append(fp.HTML, v+`\;version:\1`)
		} else {
			fp.HTML = append(fp.HTML, v)
		}
	}
	if empty(fp) {
		return nil, errors.New("whatweb: plugin " + name + " has no mappable text/regexp/version marker")
	}

	fp.Provenance = p.Name()
	fp.License = p.License()
	return map[string]schema.Fingerprint{name: fp}, nil
}
