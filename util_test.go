package mdoc

import (
	"encoding/hex"
	"io"
	"testing"
)

func NewDeterministicRand() io.Reader {
	return &deterministicRand{1, 2, 3, 4}
}

type deterministicRand []byte

func (r deterministicRand) Read(p []byte) (n int, err error) {
	write := len(p)
	if write == 0 {
		return 0, io.EOF
	}
	wrote := 0
	for wrote < write {
		wrote += copy(p[wrote:], r)
	}
	return wrote, nil
}

func decodeHex(t *testing.T, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
