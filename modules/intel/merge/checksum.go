package merge

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// The merged DB ships with a SHA-256 sidecar so a consumer can detect tamper/drift.
// The digest is lowercase hex, 64 characters; the extension names the algorithm.
const (
	ChecksumAlgo   = "sha256"
	ChecksumHexLen = 64
)

// Checksum returns the lowercase-hex SHA-256 of data. It is run over the exact bytes
// written to the merged DB file, so a later recompute over that same file must match.
// json.MarshalIndent is already stable (map keys are sorted, struct fields keep
// declaration order), so identical DB values yield identical bytes and digest.
func Checksum(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SidecarPath is the checksum file beside a merged DB (e.g. db.json → db.json.sha256).
func SidecarPath(dbPath string) string { return dbPath + "." + ChecksumAlgo }

// FormatSidecar renders the sidecar in the standard sha256sum line format
// (`<hex>  <name>`), so an operator can also verify with the system `sha256sum -c`.
func FormatSidecar(hashHex, dbName string) []byte {
	return []byte(fmt.Sprintf("%s  %s\n", hashHex, dbName))
}

// ParseSidecar reads the digest from a sha256sum-format sidecar (first whitespace
// field), rejecting anything that is not a 64-char hex string so a malformed sidecar
// is never mistaken for a match.
func ParseSidecar(content []byte) (string, error) {
	fields := strings.Fields(string(content))
	if len(fields) == 0 {
		return "", fmt.Errorf("checksum: empty sidecar")
	}
	h := strings.ToLower(fields[0])
	if len(h) != ChecksumHexLen {
		return "", fmt.Errorf("checksum: want %d-char hex digest, got %d chars", ChecksumHexLen, len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return "", fmt.Errorf("checksum: sidecar digest not hex: %w", err)
	}
	return h, nil
}
