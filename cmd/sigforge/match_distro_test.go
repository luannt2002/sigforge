package main

import "testing"

// match names the distro whose package build a banner shows, so the operator reading a version knows it is the
// upstream number of a package that may carry backported fixes; a build that is not a distro's prints as before.
func TestMatchNamesTheDistroBuild(t *testing.T) {
	for page, want := range map[string]string{
		`{"headers":{"Server":["Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips"]}}`: "Apache 2.4.6  (confidence 100, baseline/Apache-2.0, CentOS package)\n",
		`{"headers":{"X-Powered-By":["PHP/7.4.3-4ubuntu2.19"]}}`:               "PHP 7.4.3  (confidence 100, baseline/Apache-2.0, Ubuntu package)\n",
		`{"headers":{"Server":["Apache/2.4.57 (Win64) OpenSSL/3.1.1"]}}`:       "Apache 2.4.57  (confidence 100, baseline/Apache-2.0)\n",
	} {
		offline(t)
		stdinOf(t, page)
		var err error
		if out := captureStdout(t, func() { err = cmdMatch(nil) }); err != nil || out != want {
			t.Errorf("match %s = %q, %v; want %q", page, out, err, want)
		}
	}
}
