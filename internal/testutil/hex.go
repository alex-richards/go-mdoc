package testutil

import (
	"encoding/hex"
	"testing"
)

func DecodeHex(t testing.TB, encoded string) []byte {
	t.Helper()

	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	return decoded
}
