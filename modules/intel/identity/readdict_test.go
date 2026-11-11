package identity

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// ReadDict decodes what ParseDict decodes, and as it reads: a product it cannot decode stops it there, so the rest
// of a dictionary too large for memory is never taken into it.
func TestReadDictDecodesAsItReads(t *testing.T) {
	want, err := ParseDict([]byte(dictTestJSON))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := ReadDict(strings.NewReader(dictTestJSON)); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("ReadDict = %v, %v; want what ParseDict gives: %v", got, err, want)
	}
	product := `{"cpe":{"cpeName":"cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"}}`
	body := `{"products":[` + product + `,7` + strings.Repeat(","+product, 200_000) + `]}`
	r := &countingReader{r: strings.NewReader(body)}
	if _, err := ReadDict(r); err == nil {
		t.Fatal("a product that is not an object must be an error")
	}
	if r.n > 1<<20 {
		t.Fatalf("ReadDict read %d of %d bytes before the error: it must decode as it reads", r.n, len(body))
	}
}
