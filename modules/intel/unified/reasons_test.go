package unified

import (
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The reason table in docs/unified-contract.md is the consumer's list of codes: it names every code Reasons holds,
// in the same order, and no other, so a code added in one place and not the other fails here.
func TestReasonCodesDocumented(t *testing.T) {
	doc, err := os.ReadFile("../../../docs/unified-contract.md")
	if err != nil {
		t.Fatal(err)
	}
	_, section, ok := strings.Cut(string(doc), "### Reason codes")
	if !ok {
		t.Fatal(`docs/unified-contract.md has no "### Reason codes" section`)
	}
	section, _, _ = strings.Cut(section, "\n#")
	var listed []string
	for _, m := range regexp.MustCompile("(?m)^\\| `([a-z_]+)` \\|").FindAllStringSubmatch(section, -1) {
		listed = append(listed, m[1])
	}
	if !slices.Equal(listed, Reasons) {
		t.Errorf("documented reasons %v, want %v (same codes, same order)", listed, Reasons)
	}
}
