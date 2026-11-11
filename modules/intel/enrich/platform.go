package enrich

import (
	"context"
	"strconv"
	"strings"

	"github.com/luannt2002/sigforge/modules/intel/matcher"
	"github.com/luannt2002/sigforge/modules/intel/unified"
)

// pkg is one package a platform's own advisories are filed under in OSV.
type pkg struct{ eco, name string }

// platformPackages are the packages OSV files a platform's own advisories under — public package
// names, chosen and counted in the OSV dumps on 09/11/2026 (Packagist drupal/core 349 records,
// magento/community-edition 1563, typo3/cms 453; npm next 178, @angular/core 40, bootstrap 40; Maven
// org.apache.tomcat:tomcat 462, jenkins-core 510, jetty-server 70; NuGet DotNetNuke.Core 42,
// Umbraco.Cms 30). Each key is a fingerprint name; a platform detected with a release version is
// looked up as each of its packages, beside its CPE.
var platformPackages = map[string][]pkg{
	"Drupal":       {{"Packagist", "drupal/core"}, {"Packagist", "drupal/drupal"}},
	"Magento":      {{"Packagist", "magento/community-edition"}, {"Packagist", "magento/project-community-edition"}, {"Packagist", "magento/magento1ce"}},
	"Joomla":       {{"Packagist", "joomla/joomla-cms"}},
	"Laravel":      {{"Packagist", "laravel/framework"}},
	"Symfony":      {{"Packagist", "symfony/symfony"}},
	"TYPO3 CMS":    {{"Packagist", "typo3/cms-core"}, {"Packagist", "typo3/cms"}},
	"Craft CMS":    {{"Packagist", "craftcms/cms"}},
	"Silverstripe": {{"Packagist", "silverstripe/framework"}},
	"Shopware":     {{"Packagist", "shopware/platform"}, {"Packagist", "shopware/core"}, {"Packagist", "shopware/shopware"}},
	"PrestaShop":   {{"Packagist", "prestashop/prestashop"}},

	"Next.js":    {{"npm", "next"}},
	"Nuxt.js":    {{"npm", "nuxt"}},
	"Angular":    {{"npm", "@angular/core"}, {"npm", "angular"}},
	"AngularJS":  {{"npm", "angular"}},
	"React":      {{"npm", "react"}, {"npm", "react-dom"}},
	"Vue.js":     {{"npm", "vue"}},
	"jQuery":     {{"npm", "jquery"}},
	"Bootstrap":  {{"npm", "bootstrap"}},
	"Lodash":     {{"npm", "lodash"}},
	"Express":    {{"npm", "express"}},
	"Svelte":     {{"npm", "svelte"}},
	"Moment.js":  {{"npm", "moment"}},
	"Handlebars": {{"npm", "handlebars"}},
	"Ghost":      {{"npm", "ghost"}},
	"Strapi":     {{"npm", "@strapi/strapi"}, {"npm", "strapi"}},

	"Apache Tomcat": {{"Maven", "org.apache.tomcat:tomcat"}, {"Maven", "org.apache.tomcat.embed:tomcat-embed-core"}},
	"Jetty":         {{"Maven", "org.eclipse.jetty:jetty-server"}},
	"Jenkins":       {{"Maven", "org.jenkins-ci.main:jenkins-core"}},
	"Solr":          {{"Maven", "org.apache.solr:solr-core"}},
	"Liferay":       {{"Maven", "com.liferay.portal:release.portal.bom"}},
	"Spring":        {{"Maven", "org.springframework:spring-webmvc"}, {"Maven", "org.springframework:spring-core"}},

	"Umbraco": {{"NuGet", "Umbraco.Cms"}, {"NuGet", "UmbracoCms.Core"}},
	"DNN":     {{"NuGet", "DotNetNuke.Core"}},
}

// releaseLine bounds the major versions a package holds the releases of (0 = open): drupal/core is
// Drupal 8 and later (Drupal 7 is drupal/drupal), @angular/core Angular 2 and later (1.x is the
// AngularJS package "angular", which the fingerprints also name Angular), magento/community-edition
// Magento 2 (1.x is magento/magento1ce). A version of another line would fall in the package's
// "from the start" ranges: affected by advisories of a product it is not. For a version older than
// every version a package's advisories name (Shopware 5 in shopware/platform), the release lookup
// marks OutsideListed what an advisory listing the package's releases reaches only from the start;
// this table holds only the packages whose data does not show that: drupal/core and the Magento
// packages name older versions, and npm is outside that rule (measured on the dumps, 09/11/2026).
var releaseLine = map[string][2]int{
	"drupal/core":                       {8, 0},
	"@angular/core":                     {2, 0},
	"angular":                           {0, 1},
	"magento/community-edition":         {2, 0},
	"magento/project-community-edition": {2, 0},
	"magento/magento1ce":                {0, 1},
}

// inReleaseLine reports whether version's major falls in the package's line; a package without
// bounds takes any version, and a version without a readable major only those.
func inReleaseLine(name, version string) bool {
	b, ok := releaseLine[name]
	if !ok {
		return true
	}
	major, err := strconv.Atoi(strings.TrimLeft(strings.SplitN(strings.TrimSpace(version), ".", 2)[0], "vV"))
	if err != nil {
		return false
	}
	return (b[0] == 0 || major >= b[0]) && (b[1] == 0 || major <= b[1])
}

// platformResults looks a detected platform's core packages up in OSV — only with a version that
// names a release (advisories are bounded by releases, so "Drupal 9" from a header or "Magento/2.4"
// would fall inside every 9.x or 2.4.x range; without one the CVE source already lists the
// product's advisories) and only when the release lookup is on, so an off source adds no unanswered lookups.
func platformResults(ctx context.Context, d matcher.Detection, opt Options) []unified.Result {
	if opt.OSVRelease == nil || strings.Count(strings.TrimSpace(d.Version), ".") < releaseDots(d.Tech, d.Version) {
		return nil
	}
	var out []unified.Result
	for _, p := range platformPackages[d.Tech] {
		if !inReleaseLine(p.name, d.Version) {
			continue
		}
		out = append(out, keepDoubtsApart(applyVersionConflict(opt.OSVRelease(ctx, p.eco, p.name, d.Version), d))...)
	}
	return out
}

// keepDoubtsApart moves the leads the source doubts (a note on the lead: the release may not be the
// package's) into a potentially-affected result of their own, with that reason: still reported, never
// dropped, but not sizing the finding the other leads make.
func keepDoubtsApart(r unified.Result) []unified.Result {
	var sure, doubt []unified.Lead
	for _, l := range r.Leads {
		if l.Note != "" {
			doubt = append(doubt, l)
		} else {
			sure = append(sure, l)
		}
	}
	if len(doubt) == 0 || r.State != unified.StateAffectedByAdvisory {
		return []unified.Result{r}
	}
	d := r
	d.State, d.Leads, d.Err = unified.StatePotentiallyAffected, doubt, strings.TrimSuffix(doubt[0].Note+"; "+r.Err, "; ")
	if len(sure) == 0 {
		return []unified.Result{d}
	}
	r.Leads = sure
	return []unified.Result{r, d}
}

// releaseDots is how many dots a version needs to name one release: Drupal 7 and older release
// at <major>.<n> (8 and later at major.minor.patch, so "9.5" names a branch) and Jenkins weekly
// releases are 2.<n>; Shopware 6, PrestaShop 1.x and Magento 1 release at four parts (6.5.8.15,
// 1.7.8.11, 1.9.4.5, so "6.5.8" names a branch); every other platform here at major.minor.patch.
func releaseDots(tech, version string) int {
	major, err := strconv.Atoi(strings.SplitN(strings.TrimSpace(version), ".", 2)[0])
	switch {
	case tech == "Jenkins" || (tech == "Drupal" && err == nil && major < 8):
		return 1
	case err == nil && ((tech == "Shopware" && major >= 6) || (tech == "PrestaShop" && major < 8) || (tech == "Magento" && major < 2)):
		return 3
	}
	return 2
}

// dropRepeated keeps, across one detection's results in order, only the OSV leads no earlier result
// named (by id or CVE) at least as firmly; an OSV result left with none is dropped: its advisories are
// already reported, and one CVE must not become two findings. A firmer OSV lead (version-pinned where the
// earlier mention was not) is kept. rs is filtered in place.
func dropRepeated(rs []unified.Result) []unified.Result {
	named := map[string]unified.State{} // the firmest state each advisory was reported in (affected > potentially)
	out := rs[:0]
	for _, r := range rs {
		if r.Source == "osv" && len(r.Leads) > 0 {
			var kept []unified.Lead
			for _, l := range r.Leads {
				if !namedAsFirmly(l, r.State, named) {
					kept = append(kept, l)
				}
			}
			if len(kept) == 0 {
				continue
			}
			r.Leads = kept
		}
		for _, l := range r.Leads {
			for _, k := range leadKeys(l) {
				named[k] = max(named[k], r.State)
			}
		}
		out = append(out, r)
	}
	return out
}

// namedAsFirmly reports whether an earlier result named the lead in a state at least as firm as this one.
func namedAsFirmly(l unified.Lead, state unified.State, named map[string]unified.State) bool {
	for _, k := range leadKeys(l) {
		if s, ok := named[k]; ok && s >= state {
			return true
		}
	}
	return false
}

// leadKeys is every name a lead goes by: its id and the CVEs it names.
func leadKeys(l unified.Lead) []string {
	return append(leadCVEs(l), strings.ToUpper(strings.TrimSpace(l.ID)))
}
