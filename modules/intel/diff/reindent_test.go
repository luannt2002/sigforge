package diff

import (
	"encoding/json"
	"testing"

	"github.com/luannt2002/sigforge/modules/intel/schema"
)

// A DB written to disk re-indents each tech's dom JSON; read back, it is the same DB and must not report those
// techs as changed (the false "changed" refresh and diff printed for Angular and Vite). A real dom edit still is.
func TestDiffIgnoresDomReindent(t *testing.T) {
	db := func(dom string) *schema.DB {
		return &schema.DB{Fingerprints: map[string]schema.Fingerprint{"Vite": {Dom: json.RawMessage(dom)}}}
	}
	inMemory := db(`{"#vite-legacy-polyfill":{"exists":""}}`)
	if r := Diff(inMemory, db("{\n  \"#vite-legacy-polyfill\": {\n    \"exists\": \"\"\n  }\n}")); !r.Empty() {
		t.Errorf("re-indented dom read as a change: %+v", r)
	}
	if r := Diff(inMemory, db(`{"#vite-legacy-polyfill":{"exists":"x"}}`)); len(r.Changed) != 1 {
		t.Errorf("a real dom edit must still be a change: %+v", r)
	}
}
