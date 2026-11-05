package merge

import "testing"

// TestChecksumRoundTrip proves a sidecar formatted from Checksum parses back to the
// same digest, that one flipped byte changes the digest (drift is detectable), and
// that a malformed sidecar is rejected rather than mistaken for a match.
func TestChecksumRoundTrip(t *testing.T) {
	data := []byte(`{"schema_version":"1.0.0"}` + "\n")
	sum := Checksum(data)
	if len(sum) != ChecksumHexLen {
		t.Fatalf("digest len = %d, want %d", len(sum), ChecksumHexLen)
	}

	got, err := ParseSidecar(FormatSidecar(sum, "db.json"))
	if err != nil {
		t.Fatalf("parse sidecar: %v", err)
	}
	if got != sum {
		t.Fatalf("round-trip digest = %q, want %q", got, sum)
	}

	tampered := append([]byte(nil), data...)
	tampered[0] = '!'
	if Checksum(tampered) == sum {
		t.Fatal("digest unchanged after a byte flip — drift would go undetected")
	}

	if _, err := ParseSidecar([]byte("not-a-hex-digest  db.json")); err == nil {
		t.Fatal("malformed sidecar accepted")
	}
	if _, err := ParseSidecar(nil); err == nil {
		t.Fatal("empty sidecar accepted")
	}
}

func TestSidecarPath(t *testing.T) {
	if got := SidecarPath("out/db.json"); got != "out/db.json.sha256" {
		t.Fatalf("SidecarPath = %q", got)
	}
}
