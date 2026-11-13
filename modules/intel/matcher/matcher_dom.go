package matcher

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// domNode is one selector's rule in the Wappalyzer `dom` object. Only what the page's
// start tags show is evaluated: an attribute pattern is a regex over one attribute's
// value, and `exists`, an empty attribute pattern or a node with no pattern is a
// presence test of the selector. A text pattern needs the element's own text, which a
// start tag does not carry, so it is not evaluated; JS runtime `properties` cannot be
// seen passively and are ignored.
type domNode struct {
	Exists     json.RawMessage   `json:"exists"`
	Text       string            `json:"text"`
	Attributes map[string]string `json:"attributes"`
}

// domPage is the page the `dom` rules read. Its start tags are parsed at most once per
// Match, and only once some rule passes its raw-HTML filter.
type domPage struct {
	html, low string
	tags      []openTag
	parsed    bool
}

func (p *domPage) openTags() []openTag {
	if !p.parsed {
		p.tags, p.parsed = parseOpenTags(p.html), true
	}
	return p.tags
}

// matchDom evaluates a fingerprint's `dom` field. It accepts the three shapes a
// Wappalyzer dom field takes: an object of selector→rule, an array of selector strings,
// or a single selector string.
func matchDom(raw json.RawMessage, page *domPage, fp schema.Fingerprint, h *hit) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil {
		for sel, nraw := range obj {
			var node domNode
			if json.Unmarshal(nraw, &node) == nil {
				evalDomNode(sel, node, page, fp, h)
			} else {
				domPresence(sel, "", "", page, fp, h) // value was a bare string/array
			}
		}
		return
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		var one string
		if json.Unmarshal(raw, &one) != nil {
			return
		}
		list = []string{one}
	}
	for _, sel := range list {
		expr, _, _ := splitPattern(sel)
		domPresence(expr, "", sel, page, fp, h) // a list selector may end in \;confidence:N
	}
}

func evalDomNode(sel string, node domNode, page *domPage, fp schema.Fingerprint, h *hit) {
	for attr, pat := range node.Attributes {
		if expr, _, _ := splitPattern(pat); expr == "" {
			domPresence(sel, attr, pat, page, fp, h) // any value: the attribute only has to be there
			continue
		}
		domAttr(sel, attr, pat, page, fp, h)
	}
	// With no attribute/text pattern, the rule is a presence test (`exists`, or a
	// bare selector).
	if len(node.Attributes) == 0 && node.Text == "" {
		exists := ""
		if len(node.Exists) > 0 {
			_ = json.Unmarshal(node.Exists, &exists) // tolerate a non-string `exists`
		}
		domPresence(sel, "", exists, page, fp, h)
	}
}

// domAttr tests an attribute rule, e.g. [ng-version] with ng-version="([\d.]+)". The
// regex runs, unanchored and case-insensitive as in Wappalyzer, on that attribute's
// value in a start tag the selector's last compound matches, so the same text in prose,
// in an XML prolog or on a tag the selector does not name does not count.
func domAttr(sel, attr, pat string, page *domPage, fp schema.Fingerprint, h *hit) {
	expr, ver, conf := splitPattern(pat)
	attr = strings.ToLower(attr)
	if !strings.Contains(page.low, attr) {
		return
	}
	re := compile(expr)
	if re == nil {
		return
	}
	for _, b := range parseSelector(sel) {
		if b.skip || !othersMatch(b.parts, page.openTags()) {
			continue
		}
		last := b.parts[len(b.parts)-1]
		for _, t := range page.openTags() {
			a, ok := t.attr(attr)
			if !ok || !last.matches(t) {
				continue
			}
			if m := re.FindStringSubmatch(a.value); m != nil {
				end := re.FindStringIndex(a.value)[1]
				record(h, confOf(conf, fp), ver, "dom", pat, a.head+a.value[:end], m)
				return
			}
		}
	}
}

// domPresence records a hit when some branch of the selector names at least one
// literal, all of them are in the raw HTML (a cheap filter), and each compound of the
// branch matches a start tag. attr, named by an empty attribute pattern, must sit on the
// tag of the last compound, and is a literal when it has a hyphen/underscore. extra
// carries an optional `\;confidence:N`.
func domPresence(sel, attr, extra string, page *domPage, fp schema.Fingerprint, h *hit) {
	_, _, conf := splitPattern(extra)
	attr = strings.ToLower(attr)
	for _, b := range parseSelector(sel) {
		if b.skip {
			continue
		}
		last := &b.parts[len(b.parts)-1]
		if attr != "" {
			last.attrs = append(last.attrs, attrTest{name: attr})
			if strings.ContainsAny(attr, "-_") {
				b.lits = append(b.lits, attr)
			}
		}
		missing := slices.ContainsFunc(b.lits, func(l string) bool { return !strings.Contains(page.low, l) })
		if len(b.lits) == 0 || missing {
			continue
		}
		tags := page.openTags()
		if i := slices.IndexFunc(tags, last.matches); i >= 0 && othersMatch(b.parts, tags) {
			record(h, confOf(conf, fp), "", "dom", "", tags[i].src, nil)
			return // one rule is one signal, however many branches hold
		}
	}
}

// othersMatch reports whether every compound before the last matches some start tag.
// Where those tags sit is not checked: raw HTML is not parsed into a tree, so a
// descendant or sibling combinator only means "also on the page".
func othersMatch(parts []compound, tags []openTag) bool {
	for _, c := range parts[:len(parts)-1] {
		if !slices.ContainsFunc(tags, c.matches) {
			return false
		}
	}
	return true
}

// openTag is one start tag: its lowercase name, its attributes (a repeated name keeps
// its first value, as browsers do) and its source text, kept for evidence.
type openTag struct {
	name  string
	attrs []tagAttr
	src   string
}

// tagAttr is one attribute; head is its source up to the value (`ng-version="`), so
// evidence reads as the page wrote it.
type tagAttr struct {
	name, value, head string
}

func (t openTag) attr(name string) (tagAttr, bool) {
	for _, a := range t.attrs {
		if a.name == name {
			return a, true
		}
	}
	return tagAttr{}, false
}

var (
	// startTagRe finds a comment or a start tag; a quoted attribute value may hold '>'.
	startTagRe = regexp.MustCompile(`(?s)<!--.*?(?:-->|$)|<([a-zA-Z][^\s/>]*)((?:"[^"]*"|'[^']*'|[^"'>])*)>`)
	tagAttrRe  = regexp.MustCompile(`([^\s"'>/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?`)
)

// parseOpenTags lists the start tags of an HTML document in order. Comments and the
// text inside <script> and <style> are not markup, so they are skipped (the start tag
// itself is kept); end tags, <!doctype> and <?xml …?> are not start tags.
func parseOpenTags(html string) []openTag {
	var tags []openTag
	for i := 0; i < len(html); {
		loc := startTagRe.FindStringSubmatchIndex(html[i:])
		if loc == nil {
			break
		}
		at := i
		i += loc[1]
		if loc[2] < 0 {
			continue // a comment
		}
		t := openTag{name: strings.ToLower(html[at+loc[2] : at+loc[3]]), src: html[at+loc[0] : i]}
		attrs := html[at+loc[4] : at+loc[5]]
		for _, m := range tagAttrRe.FindAllStringSubmatchIndex(attrs, -1) {
			a := tagAttr{name: strings.ToLower(attrs[m[2]:m[3]]), head: attrs[m[0]:m[1]]}
			for g := 4; g < len(m); g += 2 {
				if m[g] >= 0 {
					a.head, a.value = attrs[m[0]:m[g]], attrs[m[g]:m[g+1]]
				}
			}
			if _, dup := t.attr(a.name); !dup {
				t.attrs = append(t.attrs, a)
			}
		}
		tags = append(tags, t)
		if t.name == "script" || t.name == "style" {
			i += rawTextEnd(html[i:], t.name)
		}
	}
	return tags
}

// rawTextEnd returns where the text after a <script> or <style> start tag ends: at its
// end tag, whose name (any case) is followed by whitespace, '/', '>' or the end of the
// page, so </scripts> is still text; with no such end tag, at the end of the page.
func rawTextEnd(s, name string) int {
	for i := 0; ; i += 2 {
		k := strings.Index(s[i:], "</")
		if k < 0 {
			return len(s)
		}
		i += k
		if e := i + 2 + len(name); e <= len(s) && strings.EqualFold(s[i+2:e], name) &&
			(e == len(s) || isSpace(s[e]) || s[e] == '/' || s[e] == '>') {
			return i
		}
	}
}

// compound is one compound selector (div#id.cls[attr…]); every test must hold on the
// same start tag. #x is the test [id=x] and .x the test [class~=x].
type compound struct {
	tag   string // lowercase; "" = any tag
	attrs []attrTest
}

// attrTest is [name] or [name op val] with op one of = ~= |= ^= $= *=; fold is the ` i`
// flag. The name compares lowercase, the value case-sensitively as in CSS.
type attrTest struct {
	name, op, val string
	fold          bool
}

func (c compound) matches(t openTag) bool {
	if c.tag != "" && c.tag != t.name {
		return false
	}
	for _, a := range c.attrs {
		v, ok := t.attr(a.name)
		if !ok || !a.holds(v.value) {
			return false
		}
	}
	return true
}

func (a attrTest) holds(v string) bool {
	want := a.val
	if a.fold {
		v, want = strings.ToLower(v), strings.ToLower(want)
	}
	switch a.op {
	case "":
		return true
	case "=":
		return v == want
	case "~=":
		return slices.Contains(strings.Fields(v), want)
	case "|=":
		return v == want || strings.HasPrefix(v, want+"-")
	case "^=":
		return want != "" && strings.HasPrefix(v, want)
	case "$=":
		return want != "" && strings.HasSuffix(v, want)
	case "*=":
		return want != "" && strings.Contains(v, want)
	}
	return false
}

// selBranch is one comma-separated branch of a selector: its compounds and the
// lowercase literals that gate and pre-filter it. skip marks a branch that is malformed
// or uses a pseudo-class this matcher cannot honour (:not, :is, :has, …): it never fires.
type selBranch struct {
	parts []compound
	lits  []string
	skip  bool
}

var (
	cssIdentRe = regexp.MustCompile(`^(?:[\w-]|\\.|[^\x00-\x7f])+`)
	cssAttrRe  = regexp.MustCompile(`^\[\s*((?:[\w-]|\\.)+)\s*(?:([~|^$*]?=)\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|((?:[^\s\]\\]|\\.)*)))?\s*([iIsS]?)\s*\]`)
	cssEscRe   = regexp.MustCompile(`\\(.)`)
)

// parseSelector splits a CSS selector into comma-separated branches of compounds and
// collects each branch's literals: attribute values of at least four bytes, ids
// and classes of at least six bytes or with a hyphen/underscore, and tag or
// attribute names with a hyphen/underscore (custom elements, data-*). A plain tag or
// attribute name (script, content) sits on every kind of page, so it is never a literal.
func parseSelector(sel string) []selBranch {
	out := []selBranch{{}}
	var c compound
	open := false
	end := func() {
		if open {
			out[len(out)-1].parts = append(out[len(out)-1].parts, c)
		}
		c, open = compound{}, false
	}
	lit := func(s string, ok bool) {
		if ok {
			out[len(out)-1].lits = append(out[len(out)-1].lits, strings.ToLower(s))
		}
	}
	for i := 0; i < len(sel); {
		b, rest := &out[len(out)-1], sel[i:]
		switch ch := sel[i]; {
		case ch == ',':
			end()
			out = append(out, selBranch{})
			i++
		case ch == '>' || ch == '+' || ch == '~' || isSpace(ch):
			end()
			i++
		case ch == '*':
			open = true
			i++
		case ch == '#' || ch == '.':
			raw := cssIdentRe.FindString(rest[1:])
			name := cssEscRe.ReplaceAllString(raw, "$1")
			if ch == '#' {
				c.attrs = append(c.attrs, attrTest{name: "id", op: "=", val: name})
			} else {
				c.attrs = append(c.attrs, attrTest{name: "class", op: "~=", val: name})
			}
			lit(name, len(name) >= 6 || strings.ContainsAny(name, "-_"))
			b.skip = b.skip || raw == ""
			open = true
			i += 1 + len(raw)
		case ch == '[':
			m := cssAttrRe.FindStringSubmatch(rest)
			if m == nil {
				b.skip = true
				i += 1 + max(0, strings.IndexByte(rest, ']'))
				continue
			}
			a := attrTest{
				name: strings.ToLower(cssEscRe.ReplaceAllString(m[1], "$1")),
				op:   m[2],
				val:  cssEscRe.ReplaceAllString(m[3]+m[4]+m[5], "$1"), // a CSS escape (\.) stands for the bare character
				fold: m[6] == "i" || m[6] == "I",
			}
			c.attrs = append(c.attrs, a)
			lit(a.name, strings.ContainsAny(a.name, "-_"))
			lit(a.val, len(a.val) >= 4)
			open = true
			i += len(m[0])
		case ch == ':':
			n := 1
			if strings.HasPrefix(rest, "::") {
				n = 2
			}
			raw := cssIdentRe.FindString(rest[n:])
			n += len(raw)
			if strings.HasPrefix(rest[n:], "(") {
				n += parenEnd(rest[n:])
			}
			b.skip = b.skip || !(strings.HasPrefix(rest, "::") || narrowingPseudo(strings.ToLower(raw)))
			i += n
		default:
			raw := cssIdentRe.FindString(rest)
			if raw == "" {
				b.skip = true
				i++
				continue
			}
			c.tag = strings.ToLower(cssEscRe.ReplaceAllString(raw, "$1"))
			lit(c.tag, strings.ContainsAny(c.tag, "-_"))
			open = true
			i += len(raw)
		}
	}
	end()
	for k := range out {
		out[k].skip = out[k].skip || len(out[k].parts) == 0
	}
	return out
}

// narrowingPseudo reports a structural pseudo-class (:first-child, :nth-of-type(2), …).
// Ignoring it widens the match to every tag the rest of the compound names.
func narrowingPseudo(name string) bool {
	switch name {
	case "first-child", "last-child", "only-child", "first-of-type", "last-of-type", "only-of-type":
		return true
	}
	return strings.HasPrefix(name, "nth-")
}

// parenEnd returns the length of the parenthesised argument at the start of s, through
// its closing ')' (quotes and nesting respected), or len(s) when it never closes.
func parenEnd(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"', '\'':
			k := strings.IndexByte(s[i+1:], s[i])
			if k < 0 {
				return len(s)
			}
			i += k + 1
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f'
}
