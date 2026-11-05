package source

import (
	"context"
	"errors"
	"regexp"
	"strings"

	"github.com/luannt2002/sigforge/framework/fetch"
	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// nuclei adapts ProjectDiscovery nuclei technology-detection templates (MIT). A
// template is YAML with HTTP matchers; this adapter does a BEST-EFFORT, line-based
// extraction of the clear markers — it does not run a full YAML parser.
//
// MAPPING LIMITS (honest): only `word` and `regex` matchers on `part: header` and
// `part: body` are mapped — a header word of the form "Name: value" becomes a
// header pattern, everything else becomes an HTML substring (word, regex-escaped)
// or HTML regex. NOT represented: `status`/`dsl`/`binary`/`favicon` matchers,
// extractors, `matchers-condition: and`, `negative: true`, and multi-request flow.
// Because AND/negative conditions are dropped, a normalized entry is an OR-set of
// markers and may fire where the strict template would not — which is exactly the
// "a detection is a LEAD" contract the matcher already assumes. Multiple templates
// in one document (separated by `---`) are each normalized and merged.
//
// FIELDS CARRIED beyond markers: `info.classification.cpe` is extracted into CPE
// (the CVE bridge). Nuclei templates carry NO Wappalyzer numeric category ids —
// only free-text `tags` — so there are no cats to carry from this source.
type nuclei struct {
	url    string
	client *fetch.Client
}

func (n *nuclei) Name() string    { return "nuclei" }
func (n *nuclei) License() string { return "MIT" }

func (n *nuclei) Fetch(ctx context.Context) ([]byte, error) {
	if err := requireURL(n.Name(), n.url); err != nil {
		return nil, err
	}
	return n.client.Get(ctx, n.url)
}

func (n *nuclei) Normalize(raw []byte) (map[string]schema.Fingerprint, error) {
	out := make(map[string]schema.Fingerprint)
	for _, doc := range splitYAMLDocs(string(raw)) {
		name, fp, ok := normalizeNucleiTemplate(doc)
		if !ok {
			continue
		}
		fp.Provenance = n.Name()
		fp.License = n.License()
		out[name] = fp
	}
	if len(out) == 0 {
		return nil, errors.New("nuclei: no mappable technology template in input")
	}
	return out, nil
}

// splitYAMLDocs splits a multi-document YAML stream on lines that are exactly `---`.
func splitYAMLDocs(s string) []string {
	var docs []string
	var cur []string
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) == "---" {
			docs = append(docs, strings.Join(cur, "\n"))
			cur = cur[:0]
			continue
		}
		cur = append(cur, line)
	}
	docs = append(docs, strings.Join(cur, "\n"))
	return docs
}

func normalizeNucleiTemplate(doc string) (string, schema.Fingerprint, bool) {
	var id, name string
	inInfo := false
	part := "body"
	kind := ""       // "word" or "regex"
	collecting := "" // "words" or "regex" list currently being read
	fp := schema.Fingerprint{}

	for _, line := range strings.Split(doc, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(t, "id:"):
			id = unquoteYAML(strings.TrimSpace(t[len("id:"):]))
			continue
		case t == "info:":
			inInfo = true
			continue
		case inInfo && strings.HasPrefix(t, "name:"):
			name = unquoteYAML(strings.TrimSpace(t[len("name:"):]))
			continue
		case inInfo && strings.HasPrefix(t, "cpe:"): // info.classification.cpe → the CVE bridge
			if v := unquoteYAML(strings.TrimSpace(t[len("cpe:"):])); v != "" && len(fp.CPE) == 0 {
				fp.CPE = []string{v}
			}
			continue
		case strings.HasPrefix(t, "- type:"):
			kind = unquoteYAML(strings.TrimSpace(t[len("- type:"):]))
			part, collecting = "body", ""
			continue
		case strings.HasPrefix(t, "type:"):
			kind = unquoteYAML(strings.TrimSpace(t[len("type:"):]))
			continue
		case strings.HasPrefix(t, "part:"):
			part = unquoteYAML(strings.TrimSpace(t[len("part:"):]))
			continue
		case t == "words:":
			collecting = "words"
			continue
		case t == "regex:":
			collecting = "regex"
			continue
		}
		if collecting != "" && strings.HasPrefix(t, "- ") {
			item := unquoteYAML(strings.TrimSpace(t[2:]))
			addNucleiMarker(&fp, part, kind, collecting, item)
			continue
		}
		// any other key ends the current list
		if collecting != "" {
			collecting = ""
		}
	}

	if name == "" {
		name = id
	}
	if name == "" || empty(fp) {
		return "", fp, false
	}
	return name, fp, true
}

// addNucleiMarker routes one extracted word/regex into the fingerprint. A header
// "word" of the form "Name: value" becomes a header pattern; anything else becomes
// an HTML substring (word is regex-escaped) or HTML regex.
func addNucleiMarker(fp *schema.Fingerprint, part, kind, listKind, item string) {
	if item == "" {
		return
	}
	isRegex := listKind == "regex" || kind == "regex"
	if part == "header" {
		if hn, hv, ok := strings.Cut(item, ":"); ok && strings.TrimSpace(hn) != "" && !strings.Contains(hn, " ") {
			name := strings.TrimSpace(hn)
			val := strings.TrimSpace(hv)
			if !isRegex {
				val = regexp.QuoteMeta(val)
			}
			if fp.Headers == nil {
				fp.Headers = map[string]schema.StringList{}
			}
			fp.Headers[name] = append(fp.Headers[name], val)
			return
		}
	}
	if !isRegex {
		item = regexp.QuoteMeta(item)
	}
	fp.HTML = append(fp.HTML, item)
}

func empty(fp schema.Fingerprint) bool {
	return len(fp.Headers) == 0 && len(fp.HTML) == 0 && len(fp.Cookies) == 0 && len(fp.Meta) == 0 && len(fp.ScriptSrc) == 0
}

// unquoteYAML strips a single pair of matching surrounding quotes from a scalar.
func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}
