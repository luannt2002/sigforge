package lifecycle

import "strings"

// products maps a sigforge baseline technology name to its endoflife.date product
// id. Every pair is a PUBLIC FACT: the tech on the left is the product tracked at
// endoflife.date/<id> on the right (verified against the live feed). A tech with
// no endoflife.date product (CDNs, SaaS, libraries endoflife does not track) is
// deliberately absent, so ProductFor returns false and EOLStatus stays honest
// (StateUnknown) rather than guessing.
var products = map[string]string{
	"Nginx":                  "nginx",
	"Apache":                 "apache-http-server",
	"Apache Tomcat":          "tomcat",
	"PHP":                    "php",
	"Python":                 "python",
	"Node.js":                "nodejs",
	"Ruby":                   "ruby",
	"Django":                 "django",
	"Ruby on Rails":          "rails",
	"Laravel":                "laravel",
	"Symfony":                "symfony",
	"WordPress":              "wordpress",
	"Drupal":                 "drupal",
	"Joomla":                 "joomla",
	"Magento":                "magento",
	"TYPO3 CMS":              "typo3",
	"Vue.js":                 "vue",
	"Angular":                "angular",
	"Bootstrap":              "bootstrap",
	"jQuery":                 "jquery",
	"Next.js":                "nextjs",
	"Nuxt.js":                "nuxt",
	"Microsoft ASP.NET Core": "dotnet", // ASP.NET Core ships in and shares the .NET support lifecycle
}

// ProductFor returns the endoflife.date product id for a technology name, and
// false when the tech is not tracked there.
func ProductFor(tech string) (string, bool) {
	p, ok := productsByLower[strings.ToLower(strings.TrimSpace(tech))]
	return p, ok
}

// productsByLower is products keyed case-insensitively: "nginx" on a command line is Nginx.
var productsByLower = func() map[string]string {
	m := make(map[string]string, len(products))
	for k, v := range products {
		m[strings.ToLower(k)] = v
	}
	return m
}()
