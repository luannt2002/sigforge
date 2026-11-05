// Package matcher applies a fingerprint set to a page's raw HTTP data and returns
// the technologies it leads to. It is pure: same input, same output, no network,
// no shared state.
//
// A match is a LEAD, not proof. A version captured from a `Server:` banner or a
// meta generator is attacker-controllable and can be spoofed or stripped; treat
// Confidence and Version as hints to corroborate, not facts. Confidence below 100
// means a single weak signature carried the detection.
//
// Scope: raw HTTP only — headers, cookies, HTML, meta tags and script srcs. The
// schema's `dom` rules are evaluated passively (see matcher_dom.go): with no real
// DOM, a selector's distinguishing token and its attribute/text patterns are tested
// as substrings/regexes over the raw HTML. This is a pragmatic approximation, not a
// DOM query, so it can miss a rule that depends on element structure or JS runtime
// properties; a browser-backed consumer can still read Fingerprint.Dom itself.
package matcher

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// Page is the raw HTTP evidence from one response. Header names are matched
// case-insensitively; cookies are "name=value" strings (a whole Set-Cookie line is
// fine, only the first pair is read).
type Page struct {
	Headers    map[string][]string `json:"headers,omitempty"`
	Cookies    []string            `json:"cookies,omitempty"`
	HTML       string              `json:"html,omitempty"`
	ScriptSrcs []string            `json:"scriptSrcs,omitempty"`
}

// Detection is one recognized technology and the metadata a consumer needs to
// judge the lead: the confidence it accumulated, and the provenance+license of the
// data that produced it (so the operator knows the license posture of the hit).
type Detection struct {
	Tech       string          `json:"tech"`
	Version    string          `json:"version,omitempty"`
	Confidence int             `json:"confidence"`
	Categories []int           `json:"categories,omitempty"`
	Provenance string          `json:"provenance,omitempty"`
	License    string          `json:"license,omitempty"`
	Evidence   []MatchEvidence `json:"evidence,omitempty"`
}

// MatchEvidence records why one detection fired: which field carried the signal,
// the pattern that matched, and the actual string it matched (truncated if long).
// It makes a detection traceable back to the raw signal; it is not proof of
// exploitability, only of the lead. An implied technology carries no evidence.
type MatchEvidence struct {
	Field   string `json:"field"`             // header | cookie | meta | html | scriptSrc | dom
	Pattern string `json:"pattern,omitempty"` // the matched regex; empty for a presence signal
	Matched string `json:"matched,omitempty"` // the string that actually matched
}

const maxImplyDepth = 4

type hit struct {
	conf     int
	version  string
	fp       schema.Fingerprint
	implied  bool
	evidence []MatchEvidence
}

// Match runs every fingerprint in the DB against the page and returns detections
// sorted by confidence descending, then by name.
func Match(db *schema.DB, page Page) []Detection {
	if db == nil || len(db.Fingerprints) == 0 {
		return nil
	}
	html := page.HTML
	lowHTML := strings.ToLower(html)
	headers := lowerHeaders(page.Headers)
	cookies := parseCookies(page.Cookies)
	metas := parseMetas(html)

	hits := make(map[string]*hit)
	for name, fp := range db.Fingerprints {
		h := &hit{fp: fp}
		matchNamed(fp.Headers, headers, "header", fp, h)
		matchNamed(fp.Cookies, cookies, "cookie", fp, h)
		matchNamed(fp.Meta, metas, "meta", fp, h)
		for _, raw := range fp.HTML {
			matchHTML(raw, html, lowHTML, fp, h)
		}
		for _, raw := range fp.ScriptSrc {
			for _, src := range page.ScriptSrcs {
				matchScriptSrc(raw, src, fp, h)
			}
		}
		if len(fp.Dom) > 0 {
			matchDom(fp.Dom, html, lowHTML, fp, h)
		}
		if h.conf > 0 {
			refineVersion(fp, html, headers, h)
			hits[name] = h
		}
	}

	expandImplies(db, hits)

	out := make([]Detection, 0, len(hits))
	for name, h := range hits {
		conf := h.conf
		if conf > 100 {
			conf = 100
		}
		out = append(out, Detection{
			Tech:       name,
			Version:    h.version,
			Confidence: conf,
			Categories: h.fp.Cats,
			Provenance: h.fp.Provenance,
			License:    h.fp.License,
			Evidence:   h.evidence,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Tech < out[j].Tech
	})
	return out
}

func matchNamed(pats map[string]schema.StringList, src map[string][]string, field string, fp schema.Fingerprint, h *hit) {
	if len(pats) == 0 || len(src) == 0 {
		return
	}
	for name, raws := range pats {
		vals, ok := src[strings.ToLower(strings.TrimSpace(name))]
		if !ok {
			continue
		}
		for _, raw := range raws {
			expr, ver, conf := splitPattern(raw)
			if expr == "" { // presence of the name is itself the signal
				record(h, confOf(conf, fp), ver, field, "", name, nil)
				continue
			}
			re := compile(expr)
			if re == nil {
				continue
			}
			for _, v := range vals {
				if m := re.FindStringSubmatch(v); m != nil {
					record(h, confOf(conf, fp), ver, field, expr, m[0], m)
					break
				}
			}
		}
	}
}

func matchHTML(raw, html, lowHTML string, fp schema.Fingerprint, h *hit) {
	expr, ver, conf := splitPattern(raw)
	if expr == "" {
		return // an empty HTML pattern would match every page
	}
	re := compile(expr)
	if re == nil {
		return
	}
	if lit := requiredLit(expr); lit != "" && !strings.Contains(lowHTML, lit) {
		return
	}
	if m := re.FindStringSubmatch(html); m != nil {
		record(h, confOf(conf, fp), ver, "html", expr, m[0], m)
	}
}

// matchScriptSrc matches a library pattern against one script src with a
// token-boundary guard: a pattern like `c3(?:\.min)?\.js` must not fire on the
// "c3.js" sitting inside a hashed bundle name /assets/index-a1b2c3.js, so a match
// whose start is glued to an alphanumeric on both sides is rejected.
func matchScriptSrc(raw, src string, fp schema.Fingerprint, h *hit) {
	if src == "" {
		return
	}
	expr, ver, conf := splitPattern(raw)
	if expr == "" {
		return
	}
	re := compile(expr)
	if re == nil {
		return
	}
	loc := re.FindStringSubmatchIndex(src)
	if loc == nil {
		return
	}
	if st := loc[0]; st > 0 && alnum(src[st-1]) && alnum(src[st]) {
		return
	}
	m := make([]string, 0, len(loc)/2)
	for i := 0; i+1 < len(loc); i += 2 {
		if loc[i] < 0 {
			m = append(m, "")
			continue
		}
		m = append(m, src[loc[i]:loc[i+1]])
	}
	record(h, confOf(conf, fp), ver, "scriptSrc", expr, m[0], m)
}

// refineVersion fills a still-missing version from the entry's alternate
// version_regex patterns (kept from lower-trust sources during merge). It runs
// only after the tech is already detected, so it can refine the lead's version
// but can never create a false detection.
func refineVersion(fp schema.Fingerprint, html string, headers map[string][]string, h *hit) {
	if h.version != "" || len(fp.VersionRegex) == 0 {
		return
	}
	var hay strings.Builder
	hay.WriteString(html)
	for _, vals := range headers {
		for _, v := range vals {
			hay.WriteByte('\n')
			hay.WriteString(v)
		}
	}
	s := hay.String()
	for _, raw := range fp.VersionRegex {
		expr, ver, _ := splitPattern(raw)
		re := compile(expr)
		if re == nil {
			continue
		}
		if m := re.FindStringSubmatch(s); m != nil {
			if v := substitute(ver, m); v != "" {
				h.version = v
				return
			}
		}
	}
}

func record(h *hit, conf int, verTmpl, field, pattern, matched string, m []string) {
	h.conf += conf
	// Keep the first version captured. A later pattern's differently-shaped string
	// must not overwrite it: the old len-based choice wrongly preferred "9.5" over
	// "10". refineVersion still fills a version only when none was captured.
	if h.version == "" {
		h.version = substitute(verTmpl, m)
	}
	h.evidence = append(h.evidence, MatchEvidence{Field: field, Pattern: pattern, Matched: redact(matched)})
}

// redact caps a matched string so a whole inlined script or minified blob does not
// bloat the evidence; it keeps the lead traceable without dumping the page.
func redact(s string) string {
	const max = 120
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// expandImplies propagates the "implies" relation (WordPress ⇒ PHP). An implied
// technology is never more confident than the one that implied it; depth is
// bounded so a cyclic set cannot loop.
func expandImplies(db *schema.DB, hits map[string]*hit) {
	for depth := 0; depth < maxImplyDepth; depth++ {
		added := false
		for _, h := range hits {
			for _, raw := range h.fp.Implies {
				name, _, conf := splitPattern(raw)
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				c := h.conf
				if conf > 0 {
					c = h.conf * conf / 100
				}
				if c <= 0 {
					continue
				}
				cur, ok := hits[name]
				if ok && (!cur.implied || cur.conf >= c) {
					continue
				}
				hits[name] = &hit{conf: c, fp: db.Fingerprints[name], implied: true}
				added = true
			}
		}
		if !added {
			return
		}
	}
}

// splitPattern separates "regex\;version:\1\;confidence:50" into the regex, the
// version template and the confidence (0 = unspecified, resolved by confOf).
func splitPattern(raw string) (expr, ver string, conf int) {
	parts := strings.Split(raw, `\;`)
	expr = parts[0]
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "version":
			ver = v
		case "confidence":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n > 0 && n <= 100 {
				conf = n
			}
		}
	}
	return expr, ver, conf
}

// confOf resolves the effective confidence: the pattern's own, else the entry's
// declared confidence, else a full 100.
func confOf(patConf int, fp schema.Fingerprint) int {
	if patConf > 0 {
		return patConf
	}
	if fp.Confidence > 0 {
		return fp.Confidence
	}
	return 100
}

// substitute expands a version template's `\n` backreferences from a regex match.
// shortcut: Wappalyzer's rarer `\1?a:b` ternary is not handled, so such a template
// yields a slightly off version string; upgrade here if a normalized source uses it.
func substitute(tmpl string, m []string) string {
	if tmpl == "" || len(m) == 0 {
		return ""
	}
	var b strings.Builder
	for i := 0; i < len(tmpl); i++ {
		if tmpl[i] == '\\' && i+1 < len(tmpl) && tmpl[i+1] >= '0' && tmpl[i+1] <= '9' {
			if n := int(tmpl[i+1] - '0'); n < len(m) {
				b.WriteString(m[n])
			}
			i++
			continue
		}
		b.WriteByte(tmpl[i])
	}
	v := strings.TrimSpace(b.String())
	if len(v) > 32 {
		v = v[:32]
	}
	return v
}

// compile compiles a case-insensitive pattern, returning nil for a regex RE2
// rejects (JS lookahead/backreference) — one lost signature beats failing the set.
func compile(expr string) *regexp.Regexp {
	if strings.TrimSpace(expr) == "" {
		return nil
	}
	re, err := regexp.Compile("(?i)" + expr)
	if err != nil {
		return nil
	}
	return re
}

// requiredLit returns a lowercase literal that every match of expr is guaranteed to
// contain, usable as a cheap pre-filter, or "" when none qualifies. Only runs at the
// top level of the regex (outside every group, hence mandatory) count; a top-level
// alternation makes no literal required across its branches, so such a pattern
// yields "". A run whose last letter a following `?`, `*` or `{..}` quantifier makes
// optional has that letter dropped. With these rules the pre-filter is one-way safe:
// it never rejects a page the full regex would match.
func requiredLit(expr string) string {
	best := ""
	depth := 0
	cur := strings.Builder{}
	flush := func(lastOptional bool) {
		s := cur.String()
		cur.Reset()
		if lastOptional && s != "" {
			s = s[:len(s)-1]
		}
		if len(s) > len(best) {
			best = s
		}
	}
	for i := 0; i < len(expr); i++ {
		switch c := expr[i]; {
		case c == '\\':
			flush(false)
			i++ // escaped byte is not part of a literal run
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			if depth == 0 {
				cur.WriteByte(c)
			}
		case c == '?' || c == '*' || c == '{':
			flush(true) // the run's last letter is optional
		case c == '(':
			flush(false)
			depth++
		case c == ')':
			flush(false)
			if depth > 0 {
				depth--
			}
		case c == '|':
			flush(false)
			if depth == 0 {
				return "" // top-level alternation: no literal is required
			}
		case c == '[':
			flush(false)
			for i++; i < len(expr) && expr[i] != ']'; i++ {
				if expr[i] == '\\' {
					i++
				}
			}
		default:
			flush(false)
		}
	}
	flush(false)
	if len(best) < 4 {
		return ""
	}
	return strings.ToLower(best)
}

func lowerHeaders(h map[string][]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string][]string, len(h))
	for k, v := range h {
		lk := strings.ToLower(strings.TrimSpace(k))
		out[lk] = append(out[lk], v...)
	}
	return out
}

func parseCookies(cookies []string) map[string][]string {
	if len(cookies) == 0 {
		return nil
	}
	out := make(map[string][]string, len(cookies))
	for _, c := range cookies {
		pair := c
		if i := strings.IndexByte(pair, ';'); i >= 0 {
			pair = pair[:i]
		}
		name, val, _ := strings.Cut(pair, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		out[name] = append(out[name], strings.TrimSpace(val))
	}
	return out
}

var (
	metaTagRe = regexp.MustCompile(`(?is)<meta\s[^>]{0,1000}>`)
	attrRe    = regexp.MustCompile(`(?is)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))`)
)

// parseMetas extracts <meta name|property|http-equiv=… content=…> into a
// name→values map, matching how the Wappalyzer `meta` field is keyed.
func parseMetas(html string) map[string][]string {
	tags := metaTagRe.FindAllString(html, 400)
	if len(tags) == 0 {
		return nil
	}
	out := make(map[string][]string, len(tags))
	for _, tag := range tags {
		var name, content string
		for _, a := range attrRe.FindAllStringSubmatch(tag, 12) {
			val := a[2] + a[3] + a[4]
			switch strings.ToLower(a[1]) {
			case "name", "property", "http-equiv", "itemprop":
				if name == "" {
					name = strings.ToLower(strings.TrimSpace(val))
				}
			case "content":
				content = val
			}
		}
		if name != "" {
			out[name] = append(out[name], content)
		}
	}
	return out
}

func alnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
