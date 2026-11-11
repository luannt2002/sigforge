package matcher

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// domPassiveCase applies one synthetic Wappalyzer-shaped dom rule (made-up literals,
// no upstream rule copied) to one page body.
type domPassiveCase struct {
	name string
	dom  string
	html string
	want bool
	ver  string // version expected when detected
	conf int    // confidence expected when detected; 0 = not checked
}

func runDomPassive(t *testing.T, cases []domPassiveCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := db(map[string]schema.Fingerprint{"T": {Dom: json.RawMessage(c.dom)}})
			done := make(chan []Detection, 1)
			go func() { done <- Match(d, Page{HTML: c.html}) }()
			var dets []Detection
			select {
			case dets = <-done:
			case <-time.After(10 * time.Second): // a parser loop that stops advancing fails here, not at go test's 10-minute timeout
				t.Fatal("Match did not return")
			}
			got, ok := find(dets, "T")
			if ok != c.want {
				t.Fatalf("detected=%v want=%v (got %+v)", ok, c.want, got)
			}
			if ok && got.Version != c.ver {
				t.Fatalf("version=%q want=%q", got.Version, c.ver)
			}
			if ok && c.conf != 0 && got.Confidence != c.conf {
				t.Fatalf("confidence=%d want=%d", got.Confidence, c.conf)
			}
		})
	}
}

// AC1: a text pattern needs the element's text, which raw HTML cannot isolate.
func TestDomPassiveTextNotEvaluated(t *testing.T) {
	const textRule = `{"p.demo-theme-version":{"text":"([\\d]+(?:\\.[\\d]+)*)\\;version:\\1"}}`
	runDomPassive(t, []domPassiveCase{
		{name: "digit elsewhere on the page", dom: textRule, html: `<h1>Welcome</h1>`},
		{name: "text-only rule is not a presence test", dom: textRule, html: `<p class="demo-theme-version">0.15.2</p>`},
		{name: "empty text stays a presence test", dom: `{"#demo-cookie-bar":{"text":""}}`, html: `<div id="demo-cookie-bar">ok</div>`, want: true},
	})
}

// AC2: an empty attribute pattern only says the attribute exists, so the selector decides.
func TestDomPassiveEmptyAttributeIsPresence(t *testing.T) {
	const app = `{"div#demo-app":{"attributes":{"id":"\\;confidence:50"}}}`
	const ads = `{"link[href*='.demo-ads.example.test']":{"attributes":{"href":""}}}`
	const preload = `{"a,section":{"attributes":{"data-demo-preload":""}}}`
	runDomPassive(t, []domPassiveCase{
		{name: "any id is not the app id", dom: app, html: `<div id="root"></div>`},
		{name: "app id present", dom: app, html: `<div id="demo-app"></div>`, want: true, conf: 50},
		{name: "any href is not the ad domain", dom: ads, html: `<link href="/wp-content/x.css">`},
		{name: "ad domain present", dom: ads, html: `<link href="https://cdn.demo-ads.example.test/x.css">`, want: true},
		{name: "hyphenated attribute name is the evidence", dom: preload, html: `<section data-demo-preload="hover"></section>`, want: true},
		{name: "attribute must sit on a tag the selector names", dom: preload, html: `<div data-demo-preload="hover"></div>`},
		{name: "attribute name in prose", dom: preload, html: `<section><p>set data-demo-preload on links</p></section>`},
	})
}

// AC3: a presence test needs what its selector names, branch by branch.
func TestDomPassivePresenceNeedsSelectorEvidence(t *testing.T) {
	const plugin = `["link[href*='/wp-content/plugins/demoplug/']"]`
	const author = `["meta[name='author'][content*='Demo Corp']"]`
	const video = `["iframe[src*='player.vidz.test']"]`
	const cms = `["a[href*='/demo-cms/'], meta[content*='DemoCMS']"]`
	const nested = `{"div.demo-side > div.demo-wrap":{"exists":""}}`
	runDomPassive(t, []domPassiveCase{
		{name: "theme path is not the plugin path", dom: plugin, html: `<link href="/wp-content/themes/x/style.css">`},
		{name: "plugin path present", dom: plugin, html: `<link href="/wp-content/plugins/demoplug/form.css">`, want: true},
		{name: "another meta is not the author meta", dom: author, html: `<meta name="generator" content="WordPress">`},
		{name: "every attribute value is required", dom: author, html: `<meta name="description" content="Demo Corp dealers">`},
		{name: "author meta present", dom: author, html: `<meta name="author" content="Demo Corp">`, want: true},
		{name: "another iframe is not the player", dom: video, html: `<iframe src="https://www.example.test/embed/x"></iframe>`},
		{name: "player iframe present", dom: video, html: `<iframe src="https://player.vidz.test/1"></iframe>`, want: true},
		{name: "CSS-escaped value matches the bare page value", dom: `["iframe[src*='player\\.demo-stream\\.example\\.test']"]`, html: `<iframe src="https://player.demo-stream.example.test/1"></iframe>`, want: true},
		{name: "hyphenated attribute name", dom: `{"[data-demo-hk]":{"exists":""}}`, html: `<div data-demo-hk="0"></div>`, want: true},
		{name: "custom element name", dom: `["demo-widget"]`, html: `<demo-widget></demo-widget>`, want: true},
		{name: "class of six or more characters", dom: `[".demowidget"]`, html: `<div class="demowidget"></div>`, want: true},
		{name: "short plain id is not evidence", dom: `{"#demo":{"exists":""}}`, html: `<div id="demo"></div>`},
		{name: "comma branches are alternatives", dom: cms, html: `<meta name="generator" content="DemoCMS 2">`, want: true},
		{name: "no branch satisfied", dom: cms, html: `<meta name="generator" content="WordPress">`},
		{name: "every class of a branch is required", dom: nested, html: `<div class="demo-wrap"></div>`},
		{name: "both classes present", dom: nested, html: `<div class="demo-side"><div class="demo-wrap"></div></div>`, want: true},
		{name: "tag name is never evidence", dom: `["section"]`, html: `<section>x</section>`},
		{name: "plain attribute name is never evidence", dom: `{"[demoattr]":{"exists":""}}`, html: `<p demoattr="y">x</p>`},
		{name: "value under four characters is not evidence", dom: `["div[class*='ab']"]`, html: `<div class="tab"></div>`},
	})
}

// AC4: an attribute pattern reads the named attribute of a tag the selector names.
func TestDomPassiveAttributeNameBoundary(t *testing.T) {
	const feed = `{"demo-feed":{"attributes":{"version":"([\\d.]+)\\;version:\\1"}}}`
	const cdn = `{"a":{"attributes":{"href":"demo-cdn\\.example\\.test|alt-cdn\\.example\\.test"}}}`
	runDomPassive(t, []domPassiveCase{
		{name: "version inside ng-version", dom: feed, html: `<demo-feed ng-version="16.2.0"></demo-feed>`},
		{name: "version attribute", dom: feed, html: `<demo-feed version="2.0"></demo-feed>`, want: true, ver: "2.0"},
		{name: "alternative outside the attribute", dom: cdn, html: `<p>see alt-cdn.example.test</p>`},
		{name: "alternative inside the attribute", dom: cdn, html: `<a href="https://alt-cdn.example.test/x">x</a>`, want: true},
	})
}

// AC8: a literal in prose, in another tag, or in a prolog is not the element the
// selector names; each shape has a positive control on the real element.
func TestDomPassiveProseAndOtherTagsDoNotFire(t *testing.T) {
	const sheet = `["html[xmlns\\:demo='urn:demo:sheet'], div[x\\:demosource='Spark']"]`
	const sorbet = `["body#sorbet"]`
	const plume = `["div[class*='plume']"]`
	const tick = `["table[class*='tick']"]`
	const search = `["input[value='demofind'][name='qq']"]`
	const feed = `{"demo-feed":{"attributes":{"version":"([\\d.]+)\\;version:\\1"}}}`
	runDomPassive(t, []domPassiveCase{
		{name: "attribute value as a word in prose", dom: sheet, html: `<p>Sparkling service, friendly staff.</p>`},
		{name: "attribute value on its element", dom: sheet, html: `<div x:demosource="Spark"></div>`, want: true},
		{name: "id as a word in prose", dom: sorbet, html: `<p>Built with sorbet JS.</p>`},
		{name: "id on its element", dom: sorbet, html: `<body id="sorbet"></body>`, want: true},
		{name: "class fragment as a word in prose", dom: plume, html: `<p>Our editor uses a plume icon.</p>`},
		{name: "class fragment on its element", dom: plume, html: `<div class="editor-plume"></div>`, want: true},
		{name: "class fragment on another tag", dom: tick, html: `<ul class="nav nav-ticks"><li>a</li></ul><span class="badge rounded-tick">1</span>`},
		{name: "class fragment on the named tag", dom: tick, html: `<table class="demo-ticks"></table>`, want: true},
		{name: "value as a word in prose", dom: search, html: `<p>Try demofind today.</p>`},
		{name: "values on their element", dom: search, html: `<input value="demofind" name="qq">`, want: true},
		{name: "attribute pattern in prose", dom: feed, html: `<p>To publish a feed, set version="2.0" on the root element.</p>`},
		{name: "attribute pattern on another tag", dom: feed, html: `<svg xmlns="http://www.w3.org/2000/svg" version="1.1"></svg>`},
		{name: "attribute pattern in an XML prolog", dom: feed, html: `<?xml version="1.0" encoding="UTF-8"?><html><body>hi</body></html>`},
		{name: "hyphenated attribute name in prose", dom: `{"[data-demo-hk]":{"exists":""}}`, html: `<p>the data-demo-hk attribute</p>`},
		{name: "custom element name in prose", dom: `["demo-widget"]`, html: `<p>the demo-widget tag</p>`},
		{name: "plugin path in prose", dom: `["link[href*='/wp-content/plugins/demoplug/']"]`, html: `<p>We removed /wp-content/plugins/demoplug/ last year.</p>`},
		{name: "vendor name in prose", dom: `["meta[name='author'][content*='Demo Corp']"]`, html: `<p>The author of this post compares Demo Corp tools.</p>`},
	})
}

// AC9: a selector compound matches one open tag of the page; tree relations are not
// checked, since raw HTML is not parsed into a tree.
func TestDomPassiveOpenTagMatching(t *testing.T) {
	const gen = `["meta[name='demo-gen'][content*='DemoCMS']"]`
	const pair = `["h2.demo-title + p.demo-lead"]`
	const ver = `{"[data-demo-ver]":{"attributes":{"data-demo-ver":"^([\\d.]+)$\\;version:\\1"}}}`
	runDomPassive(t, []domPassiveCase{
		{name: "attribute order is free", dom: gen, html: `<meta content="DemoCMS 3" name="demo-gen">`, want: true},
		{name: "valueless attribute", dom: `{"[data-demo-flag]":{"exists":""}}`, html: `<div data-demo-flag></div>`, want: true},
		{name: "quoted > does not end the tag", dom: `{"div[data-demo-x]":{"exists":""}}`, html: `<div title="1 > 0" data-demo-x="y"></div>`, want: true},
		{name: "tag and attribute names ignore case", dom: `{"demo-feed":{"attributes":{"version":"([\\d.]+)\\;version:\\1"}}}`, html: `<DEMO-FEED VERSION="3.1"></DEMO-FEED>`, want: true, ver: "3.1"},
		{name: "id compares case-sensitively", dom: `["div#demo-panel"]`, html: `<DIV ID="DEMO-PANEL"></DIV>`},
		{name: "op = whole value", dom: `["a[rel='demo-rel']"]`, html: `<a rel="demo-rel">x</a>`, want: true},
		{name: "op = not a part", dom: `["a[rel='demo-rel']"]`, html: `<a rel="demo-rel x">x</a>`},
		{name: "op ^= prefix", dom: `["a[href^='https://demo.example.test/']"]`, html: `<a href="https://demo.example.test/x">x</a>`, want: true},
		{name: "op ^= not inside", dom: `["a[href^='https://demo.example.test/']"]`, html: `<a href="/r?u=https://demo.example.test/">x</a>`},
		{name: "op $= suffix", dom: `["link[href$='.demo.css']"]`, html: `<link href="/a/b.demo.css">`, want: true},
		{name: "op $= not before the end", dom: `["link[href$='.demo.css']"]`, html: `<link href="/a/b.demo.css?v=1">`},
		{name: "op ~= one word", dom: `["div[class~='demo-card']"]`, html: `<div class="x demo-card y"></div>`, want: true},
		{name: "op ~= not a word prefix", dom: `["div[class~='demo-card']"]`, html: `<div class="demo-cards"></div>`},
		{name: "op |= value or value-", dom: `["html[lang|='demo']"]`, html: `<html lang="demo-x"></html>`, want: true},
		{name: "op |= not a longer word", dom: `["html[lang|='demo']"]`, html: `<html lang="demox"></html>`},
		{name: "flag i folds case", dom: `["img[alt*='demologo' i]"]`, html: `<img alt="DemoLogo">`, want: true},
		{name: "no flag keeps case", dom: `["img[alt*='demologo']"]`, html: `<img alt="DemoLogo">`},
		{name: "two conditions on two tags", dom: gen, html: `<meta name="demo-gen" content="x"><meta name="y" content="DemoCMS">`},
		{name: "class and attribute on two tags", dom: `{".demo-twic":{"attributes":{"data-src":""}}}`, html: `<img class="other" data-src="a.png"><span class="demo-twic"></span>`},
		{name: "class and attribute on one tag", dom: `{".demo-twic":{"attributes":{"data-src":""}}}`, html: `<img class="demo-twic" data-src="a.png">`, want: true},
		{name: "script content is not a tag", dom: `[".demo-widget-x"]`, html: `<script>var s = '<div class="demo-widget-x"></div>';</script>`},
		{name: "style content is not a tag", dom: `["demo-widget"]`, html: `<style>p::after{content:"<demo-widget>"}</style>`},
		{name: "comment is not a tag", dom: `[".demo-widget-x"]`, html: `<!-- <div class="demo-widget-x"></div> -->`},
		{name: "script open tag is a tag", dom: `["script#demo-loader"]`, html: `<script id="demo-loader">x</script>`, want: true},
		{name: "every compound must match", dom: pair, html: `<h2 class="demo-title">t</h2>`},
		{name: "every compound matched", dom: pair, html: `<h2 class="demo-title">t</h2><p class="demo-lead">l</p>`, want: true},
		{name: "tree relations are not checked", dom: pair, html: `<p class="demo-lead">l</p><h2 class="demo-title">t</h2>`, want: true},
		{name: ":not( drops its branch", dom: `["div.demo-widget:not(.demo-hidden)"]`, html: `<div class="demo-widget"></div>`},
		{name: "other branches still count", dom: `["div.demo-widget:not(.demo-hidden), span.demo-badge"]`, html: `<span class="demo-badge"></span>`, want: true},
		{name: "unknown pseudo-class drops its branch", dom: `["a.demo-link:hover"]`, html: `<a class="demo-link">x</a>`},
		{name: "narrowing pseudo-class is ignored", dom: `["li.demo-item:first-child"]`, html: `<li class="demo-item">x</li>`, want: true},
		{name: "pseudo-element is ignored", dom: `["span.demo-icon::before"]`, html: `<span class="demo-icon"></span>`, want: true},
		{name: "comma inside parentheses does not split", dom: `["div.demo-x:not(.demo-y, .demo-z)"]`, html: `<div class="demo-z"></div>`},
		{name: "comma inside brackets does not split", dom: `["meta[content='demo, cms']"]`, html: `<meta content="demo, cms">`, want: true},
		{name: "value of three characters is not evidence", dom: `["div[class*='abc']"]`, html: `<div class="abc"></div>`},
		{name: "value of four characters is evidence", dom: `["div[class*='abcd']"]`, html: `<div class="abcd"></div>`, want: true},
		{name: "id of five characters is not evidence", dom: `["#abcde"]`, html: `<div id="abcde"></div>`},
		{name: "id of six characters is evidence", dom: `["#abcdef"]`, html: `<div id="abcdef"></div>`, want: true},
		{name: "confidence suffix on a list selector", dom: `["div#demo-login\\;confidence:40"]`, html: `<div id="demo-login"></div>`, want: true, conf: 40},
		{name: "a bare string selector", dom: `"div#demo-single"`, html: `<div id="demo-single"></div>`, want: true},
		{name: "attribute pattern inside the value", dom: `{"link[href*='demo-cdn']":{"attributes":{"href":"demo@([\\d.]+)\\;version:\\1"}}}`, html: `<link href="https://demo-cdn.example.test/npm/demo@5.3.0/dist/x.css">`, want: true, ver: "5.3.0"},
		{name: "^…$ anchor to the value", dom: ver, html: `<div data-demo-ver="2.4.1"></div>`, want: true, ver: "2.4.1"},
		{name: "^…$ reject a longer value", dom: ver, html: `<div data-demo-ver="v2.4.1"></div>`},
		{name: "attribute pattern ignores case", dom: `{"demo-feed":{"attributes":{"data-demo-kind":"rss"}}}`, html: `<demo-feed data-demo-kind="RSS"></demo-feed>`, want: true},
		{name: "attribute pattern needs the other compounds", dom: `{"div.demo-shell span":{"attributes":{"data-demo-v":"(\\d+)\\;version:\\1"}}}`, html: `<span data-demo-v="3"></span>`},
		{name: "attribute pattern with the other compounds", dom: `{"div.demo-shell span":{"attributes":{"data-demo-v":"(\\d+)\\;version:\\1"}}}`, html: `<div class="demo-shell"><span data-demo-v="3"></span></div>`, want: true, ver: "3"},
		{name: "properties are ignored: presence of the selector", dom: `{"#demo-root":{"properties":{"__demo":""}}}`, html: `<div id="demo-root"></div>`, want: true},
		{name: "one rule is one signal however many branches hold", dom: `["div#demo-one, span#demo-two\\;confidence:40"]`, html: `<div id="demo-one"></div><span id="demo-two"></span>`, want: true, conf: 40},
		{name: "a repeated attribute keeps its first value", dom: `["div[data-demo-dup='alpha']"]`, html: `<div data-demo-dup="beta" data-demo-dup="alpha"></div>`},
		{name: "the first of repeated attributes counts", dom: `["div[data-demo-dup='alpha']"]`, html: `<div data-demo-dup="alpha" data-demo-dup="beta"></div>`, want: true},
		{name: "script end tag in any case", dom: `[".demo-widget-x"]`, html: `<script>var s;</SCRIPT><div class="demo-widget-x"></div>`, want: true},
		{name: "malformed selector never fires", dom: `["div[data-demo-x"]`, html: `<div data-demo-x="1"></div>`},
	})
}

// AC9, start tags: what ends a comment or a script/style text, and how values are quoted.
func TestDomPassiveStartTagEdges(t *testing.T) {
	const widget = `[".demo-widget-x"]`
	runDomPassive(t, []domPassiveCase{
		{name: "closed comment then a tag", dom: widget, html: `<!-- note --><div class="demo-widget-x"></div>`, want: true},
		{name: "unclosed comment runs to the end of the page", dom: widget, html: `<p>a</p><!-- <div class="demo-widget-x"></div>`},
		{name: "single-quoted value may hold >", dom: `["div[data-demo-q='alpha']"]`, html: `<div title='a > b' data-demo-q='alpha'></div>`, want: true},
		{name: "unquoted value", dom: `["div[data-demo-u='alpha']"]`, html: `<div data-demo-u=alpha></div>`, want: true},
		{name: "empty script element", dom: widget, html: `<script></script><div class="demo-widget-x"></div>`, want: true},
		{name: "script end tag right after a stray </", dom: widget, html: `<script></</script><div class="demo-widget-x"></div>`, want: true},
		{name: "end tag of another element inside a script", dom: widget, html: `<script>var a = '</p>'; var s = '<div class="demo-widget-x">';</script>`},
		{name: "space after </ does not end a script", dom: widget, html: `<script>a = 1;</ script><div class="demo-widget-x"></div></script>`},
		{name: "script without end tag runs to the end of the page", dom: widget, html: `<script>var s = '<div class="demo-widget-x"></div>';`},
		{name: "script end tag with a space before >", dom: widget, html: `<script>x</script ><div class="demo-widget-x"></div>`, want: true},
		{name: "style end tag in capitals", dom: widget, html: `<style>p{}</STYLE><div class="demo-widget-x"></div>`, want: true},
		{name: "style end tag", dom: widget, html: `<style>p{}</style><div class="demo-widget-x"></div>`, want: true},
		{name: "script end tag with a / before >", dom: widget, html: `<script>x</script/><div class="demo-widget-x"></div>`, want: true},
		{name: "script end tag with a tab before >", dom: widget, html: "<script>x</script\t><div class=\"demo-widget-x\"></div>", want: true},
		{name: "</scripts> inside a script is text", dom: widget, html: `<script>var a = '</scripts>'; var s = '<div class="demo-widget-x">';</script>`},
		{name: "</styles> inside a style is text", dom: widget, html: `<style>/* </styles> <div class="demo-widget-x"> */</style>`},
		{name: "another end tag then a space inside a script", dom: widget, html: `<script>var t = '</table> <div class="demo-widget-x">';</script>`},
		{name: "page cut off right after </script", dom: widget, html: `<script>var s = '<div class="demo-widget-x">';</script`},
	})
}

// AC9, selectors: combinators, names, escapes, quoting, flags and pseudo-classes.
func TestDomPassiveSelectorEdges(t *testing.T) {
	const item = `<li class="demo-item">x</li>`
	const badge = `<span class="demo-badge"></span>`
	runDomPassive(t, []domPassiveCase{
		{name: "combinator ~", dom: `["h2.demo-title ~ p.demo-lead"]`, html: `<h2 class="demo-title">t</h2><p class="demo-lead">l</p>`, want: true},
		{name: "universal selector", dom: `["*.demo-panel"]`, html: `<p class="demo-panel">x</p>`, want: true},
		{name: "id under six characters with a hyphen", dom: `["#de-mo"]`, html: `<div id="de-mo"></div>`, want: true},
		{name: "class under six characters with an underscore", dom: `[".de_mo"]`, html: `<div class="de_mo"></div>`, want: true},
		{name: "tag name with an underscore only", dom: `["demo_widget"]`, html: `<demo_widget></demo_widget>`, want: true},
		{name: "attribute name with an underscore only", dom: `["[demo_flag]"]`, html: `<div demo_flag></div>`, want: true},
		{name: "tag name in capitals", dom: `["DEMO-WIDGET"]`, html: `<demo-widget></demo-widget>`, want: true},
		{name: "attribute name in capitals", dom: `["div[Data-Demo-X]"]`, html: `<div data-demo-x></div>`, want: true},
		{name: "CSS escape in an id", dom: `["div#demo\\:panel"]`, html: `<div id="demo:panel"></div>`, want: true},
		{name: "non-ASCII class", dom: `[".démo-panel"]`, html: `<div class="démo-panel"></div>`, want: true},
		{name: "double-quoted value", dom: `["div[data-demo-x=\"alpha\"]"]`, html: `<div data-demo-x="alpha"></div>`, want: true},
		{name: "CSS escape in a double-quoted value", dom: `["iframe[src*=\"player\\.demo-dq\\.example\\.test\"]"]`, html: `<iframe src="https://player.demo-dq.example.test/1"></iframe>`, want: true},
		{name: "unquoted selector value", dom: `["div[data-demo-x=alpha]"]`, html: `<div data-demo-x="alpha"></div>`, want: true},
		{name: "CSS escape in an unquoted value", dom: `["div[data-demo-x=demo\\.alpha]"]`, html: `<div data-demo-x="demo.alpha"></div>`, want: true},
		{name: "flag i folds the selector value too", dom: `["img[alt*='DemoLogo' i]"]`, html: `<img alt="DEMOLOGO">`, want: true},
		{name: "flag I", dom: `["img[alt*='demologo' I]"]`, html: `<img alt="DemoLogo">`, want: true},
		{name: "flag s keeps case", dom: `["img[alt*='demologo' s]"]`, html: `<img alt="DemoLogo">`},
		{name: ":last-child is ignored", dom: `["li.demo-item:last-child"]`, html: item, want: true},
		{name: ":only-child is ignored", dom: `["li.demo-item:only-child"]`, html: item, want: true},
		{name: ":first-of-type is ignored", dom: `["li.demo-item:first-of-type"]`, html: item, want: true},
		{name: ":last-of-type is ignored", dom: `["li.demo-item:last-of-type"]`, html: item, want: true},
		{name: ":only-of-type is ignored", dom: `["li.demo-item:only-of-type"]`, html: item, want: true},
		{name: ":nth-child(2) is ignored", dom: `["li.demo-item:nth-child(2)"]`, html: item, want: true},
		{name: "pseudo-class name in capitals", dom: `["li.demo-item:First-Child"]`, html: item, want: true},
		{name: "escaped ) inside a pseudo-element argument", dom: `["span.demo-icon::part(demo\\)x)"]`, html: `<span class="demo-icon"></span>`, want: true},
		{name: "nested parentheses", dom: `["div.demo-x:not(:is(.demo-y, .demo-z)), span.demo-badge"]`, html: badge, want: true},
		{name: "empty quotes inside parentheses", dom: `["div.demo-x:not([title='']), span.demo-badge"]`, html: badge, want: true},
		{name: "unclosed quote inside parentheses runs to the end", dom: `["div.demo-x:not([title='a), span.demo-badge"]`, html: badge},
		{name: "unclosed parenthesis drops its branch", dom: `["div.demo-x:not(.demo-y"]`, html: `<div class="demo-x"></div>`},
		{name: ":not( before a class still drops its branch", dom: `["div:not(.demo-off).demo-panel"]`, html: `<div class="demo-panel"></div>`},
		{name: "three colons drop the branch", dom: `["p.demo-panel:::before"]`, html: `<p class="demo-panel"></p>`},
		{name: "stray character drops its branch", dom: `["!p.demo-panel"]`, html: `<p class="demo-panel">x</p>`},
		{name: "unclosed bracket drops its branch", dom: `["p[data-demo-x [data-demo-x]"]`, html: `<p data-demo-x="1"></p>`},
		{name: "malformed bracket does not swallow the next branch", dom: `["p[=x],span.demo-badge"]`, html: badge, want: true},
		{name: "empty branch is skipped", dom: `["div#demo-one, , span#demo-two"]`, html: `<span id="demo-two"></span>`, want: true},
	})
}

// AC9, rule shapes: list entries, attribute keys and compounds of presence rules.
func TestDomPassiveRuleEdges(t *testing.T) {
	const notShell = `{"div.demo-shell:not(.demo-off), span.demo-shell":{"attributes":{"data-demo-v":"(\\d+)\\;version:\\1"}}}`
	runDomPassive(t, []domPassiveCase{
		{name: "a later list selector counts", dom: `["div#demo-none", "div#demo-second"]`, html: `<div id="demo-second"></div>`, want: true},
		{name: "attribute pattern key in capitals", dom: `{"demo-feed":{"attributes":{"Data-Demo-Kind":"rss"}}}`, html: `<demo-feed data-demo-kind="rss"></demo-feed>`, want: true},
		{name: "attribute pattern: :not( drops its branch", dom: notShell, html: `<div class="demo-shell" data-demo-v="3"></div>`},
		{name: "attribute pattern: other branches still count", dom: notShell, html: `<span class="demo-shell" data-demo-v="3"></span>`, want: true, ver: "3"},
		{name: "empty attribute pattern key in capitals", dom: `{"section":{"attributes":{"Data-Demo-Preload":""}}}`, html: `<section data-demo-preload="hover"></section>`, want: true},
		{name: "empty attribute pattern: underscore-only name is the evidence", dom: `{"section":{"attributes":{"demo_preload":""}}}`, html: `<section demo_preload></section>`, want: true},
		{name: "an earlier compound only on another tag", dom: `["div.demo-shell p.demo-lead"]`, html: `<span class="demo-shell"></span><p class="demo-lead">x</p>`},
	})
}
