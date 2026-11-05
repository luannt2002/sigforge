package matcher

import (
	"encoding/json"
	"regexp"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// domNode is one selector's rule in the Wappalyzer `dom` object. Only the fields
// observable without a real DOM are read: attribute patterns and a text pattern
// become regexes over the raw HTML, and `exists` (or an otherwise-empty node)
// becomes a presence test of the selector's distinguishing token. JS runtime
// `properties` cannot be seen passively and are ignored.
type domNode struct {
	Exists     json.RawMessage   `json:"exists"`
	Text       string            `json:"text"`
	Attributes map[string]string `json:"attributes"`
}

// matchDom evaluates a fingerprint's `dom` field against the HTML. It accepts the
// three shapes a Wappalyzer dom field takes: an object of selector→rule, an array
// of selector strings, or a single selector string.
func matchDom(raw json.RawMessage, html, lowHTML string, fp schema.Fingerprint, h *hit) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for sel, nraw := range obj {
			var node domNode
			if json.Unmarshal(nraw, &node) == nil {
				evalDomNode(sel, node, html, lowHTML, fp, h)
			} else {
				domPresence(sel, "", lowHTML, fp, h) // value was a bare string/array
			}
		}
		return
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, sel := range arr {
			domPresence(sel, "", lowHTML, fp, h)
		}
		return
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		domPresence(one, "", lowHTML, fp, h)
	}
}

func evalDomNode(sel string, node domNode, html, lowHTML string, fp schema.Fingerprint, h *hit) {
	for attr, pat := range node.Attributes {
		domAttr(attr, pat, html, fp, h)
	}
	if node.Text != "" {
		domRegex(node.Text, html, fp, h)
	}
	// With no attribute/text pattern, the rule is a presence test (`exists`, or a
	// bare selector).
	if len(node.Attributes) == 0 && node.Text == "" {
		exists := ""
		if len(node.Exists) > 0 {
			_ = json.Unmarshal(node.Exists, &exists) // tolerate a non-string `exists`
		}
		domPresence(sel, exists, lowHTML, fp, h)
	}
}

// domAttr tests an attribute rule, e.g. ng-version="([\d.]+)". The attribute name
// anchors the pattern to a real attribute occurrence, so it cannot fire on the same
// token sitting in body text. An empty value pattern means "attribute present".
func domAttr(attr, pat, html string, fp schema.Fingerprint, h *hit) {
	expr, ver, conf := splitPattern(pat)
	re := compile(regexp.QuoteMeta(attr) + `\s*=\s*["']?` + expr)
	if re == nil {
		return
	}
	if m := re.FindStringSubmatch(html); m != nil {
		record(h, confOf(conf, fp), ver, "dom", pat, m[0], m)
	}
}

func domRegex(pat, html string, fp schema.Fingerprint, h *hit) {
	expr, ver, conf := splitPattern(pat)
	re := compile(expr)
	if re == nil {
		return
	}
	if m := re.FindStringSubmatch(html); m != nil {
		record(h, confOf(conf, fp), ver, "dom", expr, m[0], m)
	}
}

// domPresence records a hit when the selector's distinguishing token appears in the
// HTML. extra carries an optional `\;confidence:N` from an `exists` value.
func domPresence(sel, extra, lowHTML string, fp schema.Fingerprint, h *hit) {
	tok := selectorToken(sel)
	if tok == "" {
		return
	}
	_, _, conf := splitPattern(extra)
	if strings.Contains(lowHTML, tok) {
		record(h, confOf(conf, fp), "", "dom", "", tok, nil)
	}
}

var domTokenRe = regexp.MustCompile(`[A-Za-z0-9_-]+`)

// selectorToken returns the longest distinctive identifier in a CSS selector (an id,
// class, attribute name or custom-element tag) as a lowercase literal to search for.
// "Distinctive" = at least six letters, or containing a hyphen/underscore — so a
// generic tag like div/span/script is rejected and never causes a false positive.
func selectorToken(sel string) string {
	best := ""
	for _, t := range domTokenRe.FindAllString(sel, -1) {
		distinctive := len(t) >= 6 || strings.ContainsAny(t, "-_")
		if distinctive && len(t) > len(best) {
			best = t
		}
	}
	return strings.ToLower(best)
}
